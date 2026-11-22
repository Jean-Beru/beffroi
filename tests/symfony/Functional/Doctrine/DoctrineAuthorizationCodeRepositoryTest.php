<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use function array_map;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\ClaimRequest;
use Beffroi\Oidc\Domain\Authorization\ClaimsRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Grant\GrantRecord;
use Beffroi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Beffroi\Oidc\Port\LoggedInClientsInterface;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use ReflectionClass;
use function sort;
use Symfony\Component\Uid\Uuid;
use Beffroi\Oidc\Tests\Fixture\Shapes;

/**
 * Architecture §4.4, §5.3
 */
final class DoctrineAuthorizationCodeRepositoryTest extends DatabaseTestCase
{
    public const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * RFC 6749 §4.1.2, RFC 9700 §4.5
     */
    #[Test]
    public function onlyTheFirstCallerConsumesTheCode(): void
    {
        // Given
        $session = self::session(self::user());
        $code = Secrets::draw();
        self::codes()->save(self::code($code, self::client(), $session, null));
        self::reload();
        $record = self::codes()->findByCodeHash(DrawnSecret::digestOf($code)) ?? static::fail('The code was not stored.');

        // When
        $first = self::codes()->consume($record, self::now());
        $second = self::codes()->consume($record, self::now()->modify('+1 second'));

        // Then
        static::assertTrue($first);
        static::assertFalse($second);
        static::assertEquals(self::now(), $record->usedAt);
    }

    #[Test]
    public function aCodeComesBackWithWhatTheGrantNeeds(): void
    {
        // Given
        $session = self::session(self::user());
        $client = self::client();
        $claims = new ClaimsRequest([
            'email' => new ClaimRequest(true),
        ]);
        $code = Secrets::draw();
        self::codes()->save(self::code($code, $client, $session, $claims));
        self::reload();

        // When
        $found = self::codes()->findByCodeHash(DrawnSecret::digestOf($code)) ?? static::fail('The code was not stored.');

        // Then
        static::assertSame(DrawnSecret::digestOf($code), $found->codeHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('oidc-demo', $found->client->registration->clientId);
        static::assertTrue($found->session->id->equals($session->id));
        static::assertSame((string) $client->registration->redirectUris[0], (string) $found->redirectUri);
        static::assertEquals([new Scope('openid'), new Scope('email')], $found->scopes->all);
        static::assertSame('n-0S6_WzA2Mj', $found->nonce);
        static::assertSame(self::CHALLENGE, $found->codeChallenge?->value);
        static::assertTrue($found->codeChallenge->verifies('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
        static::assertEquals($claims, $found->claimsRequest);
        static::assertEquals(self::now(), $found->authentication->authenticatedAt);
        static::assertSame(['pwd'], $found->authentication->methods);
        static::assertSame('1', $found->authentication->contextClass);
        static::assertEquals(self::now()->modify('+1 minute'), $found->issuedAt);
        static::assertEquals(self::now()->modify('+2 minutes'), $found->expiresAt);
        static::assertNull($found->usedAt);
        static::assertFalse($found->isUsed());
    }

    /**
     * Architecture §4.5
     */
    #[Test]
    public function theSessionOfACodeIsReadWithThePersonItNames(): void
    {
        // Given
        $code = Secrets::draw();
        self::codes()->save(self::code($code, self::client(), self::session(self::user()), null));
        self::reload();
        $found = self::codes()->findByCodeHash(DrawnSecret::digestOf($code)) ?? static::fail('The code was not stored.');

        // When
        $person = $found->session->user;

        // Then
        static::assertFalse(new ReflectionClass($person)->isUninitializedLazyObject($person));
    }

    #[Test]
    public function aConsumedCodeStaysConsumed(): void
    {
        // Given
        $code = Secrets::draw();
        $record = self::code($code, self::client(), self::session(self::user()), null);
        self::codes()->save($record);
        $record->consume(self::now()->modify('+90 seconds'));
        self::codes()->save($record);
        self::reload();

        // When
        $found = self::codes()->findByCodeHash(DrawnSecret::digestOf($code)) ?? static::fail('The code was not stored.');

        // Then
        static::assertTrue($found->isUsed());
        static::assertEquals(self::now()->modify('+90 seconds'), $found->usedAt);
    }

    #[Test]
    public function anUnknownCodeIsNotFound(): void
    {
        // When / Then
        static::assertNull(self::codes()->findByCodeHash(DrawnSecret::digestOf(Secrets::draw())));
    }

    #[Test]
    public function aCodeOfAnUnregisteredClientIsNotFound(): void
    {
        // Given
        $ghost = new Client(
            self::tenant(),
            new ClientRegistration(
                'ghost',
                new ClientPresentation('Removed client'),
                Methods::none(),
                false,
                [new RedirectUri('https://ghost.example/callback')],
                Shapes::jwt(),
            ),
        );
        $code = Secrets::draw();
        self::codes()->save(self::code($code, $ghost, self::session(self::user()), null));
        self::reload();

        // When / Then
        static::assertNull(self::codes()->findByCodeHash(DrawnSecret::digestOf($code)));
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function theClientsOfASessionAreThoseThatExchangedACodeInIt(): void
    {
        // Given
        $session = self::session(self::user());
        self::used($session, self::client(), 'first-of-the-demo');
        self::used($session, self::client(), 'second-of-the-demo');
        self::used($session, self::client('legacy-app'), 'of-the-legacy-app');
        self::codes()->save(self::code(Secrets::draw(), self::client('native-app'), $session, null));
        self::reload();

        // When
        $clients = array_map(static fn (Client $client): string => $client->registration->clientId, self::loggedInClients()->ofSession($session->id));

        // Then
        sort($clients);
        static::assertSame(['legacy-app', 'oidc-demo'], $clients);
    }

    #[Test]
    public function theClientsOfAnotherSessionAreNotListed(): void
    {
        // Given
        $user = self::user();
        $session = self::session($user);
        self::used(self::session($user, self::now()->modify('+1 second')), self::client(), 'of-the-other-session');
        self::reload();

        // When / Then
        static::assertSame([], self::loggedInClients()->ofSession($session->id));
    }

    #[Test]
    public function aClientNoLongerRegisteredIsNotListed(): void
    {
        // Given
        $session = self::session(self::user());
        $ghost = new Client(
            self::tenant(),
            new ClientRegistration(
                'ghost',
                new ClientPresentation('Removed client'),
                Methods::none(),
                false,
                [new RedirectUri('https://ghost.example/callback')],
                Shapes::jwt(),
            ),
        );
        self::used($session, $ghost, 'of-the-ghost');
        self::reload();

        // When / Then
        static::assertSame([], self::loggedInClients()->ofSession($session->id));
    }

    private static function used(AuthenticationSession $session, Client $client, string $code): AuthorizationCode
    {
        $record = self::code($code, $client, $session, null);
        $record->consume(self::now()->modify('+90 seconds'));
        self::codes()->save($record);

        return $record;
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function theGrantsRevokedWithAConsentAreThoseOfItsUserAndItsClient(): void
    {
        // Given
        $alice = self::user();
        $session = self::session($alice);
        $exchanged = self::used($session, self::client(), 'first-of-the-demo');
        $waiting = self::code('waiting-of-the-demo', self::client(), self::session($alice, self::now()->modify('+1 second')), null);
        self::codes()->save($waiting);
        self::used($session, self::client('native-app'), 'of-the-native-app');
        self::used(self::session(self::user('bob', 'bob-subject')), self::client(), 'of-bob');
        $expected = [$exchanged->grantId->toRfc4122(), $waiting->grantId->toRfc4122()];
        sort($expected);
        self::reload();

        // When
        $grants = self::grantsOfAConsent()->revokeByConsent(self::consent($alice, self::client()), self::now());

        // Then
        $revoked = array_map(static fn (GrantRecord $grant): string => $grant->grantId->toRfc4122(), $grants);
        sort($revoked);
        static::assertSame($expected, $revoked);
    }

    #[Test]
    public function aGrantOfAClientNoLongerRegisteredIsNotListed(): void
    {
        // Given
        $alice = self::user();
        $ghost = new Client(
            self::tenant(),
            new ClientRegistration(
                'ghost',
                new ClientPresentation('Removed client'),
                Methods::none(),
                false,
                [new RedirectUri('https://ghost.example/callback')],
                Shapes::jwt(),
            ),
        );
        self::used(self::session($alice), $ghost, 'of-the-ghost');
        self::reload();

        // When / Then
        static::assertSame([], self::grantsOfAConsent()->revokeByConsent(self::consent($alice, $ghost), self::now()));
    }

    private static function consent(User $user, Client $client): Consent
    {
        return new Consent(Uuid::v7(), $user, $client, new Scopes([new Scope('openid')]), self::now());
    }

    private static function grantsOfAConsent(): CanRevokeGrantsByConsentInterface
    {
        return self::service('test.beffroi.grants_of_a_consent', CanRevokeGrantsByConsentInterface::class);
    }

    private static function loggedInClients(): LoggedInClientsInterface
    {
        return self::service('test.beffroi.logged_in_clients', LoggedInClientsInterface::class);
    }

    private static function code(string $code, Client $client, AuthenticationSession $session, ?ClaimsRequest $claims): AuthorizationCode
    {
        return new AuthorizationCode(
            DrawnSecret::digestOf($code),
            Uuid::v7(),
            $client,
            $session,
            $client->registration->redirectUris[0],
            new Scopes([new Scope('openid'), new Scope('email')]),
            null,
            null,
            'n-0S6_WzA2Mj',
            new CodeChallenge(self::CHALLENGE, new Sha256CodeChallengeMethod()),
            null,
            $claims,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            self::now()->modify('+1 minute'),
            self::now()->modify('+2 minutes'),
        );
    }

    private static function codes(): AuthorizationCodeRepositoryInterface
    {
        return self::service('test.beffroi.authorization_codes', AuthorizationCodeRepositoryInterface::class);
    }
}
