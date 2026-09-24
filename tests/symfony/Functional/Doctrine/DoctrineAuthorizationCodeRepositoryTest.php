<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_map;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\LoggedInClientsInterface;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §4.4, §5.3: a code keyed by its hash, with everything the token endpoint needs, back with
 * the client the configuration registers; a used code stays.
 */
final class DoctrineAuthorizationCodeRepositoryTest extends DatabaseTestCase
{
    public const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * RFC 6749 §4.1.2, RFC 9700 §4.5: the claim is one conditional statement, so a second caller is told
     * it lost whatever it read before, and it holds the date the first one wrote.
     */
    #[Test]
    public function onlyTheFirstCallerConsumesTheCode(): void
    {
        // Given
        $session = self::session(self::user());
        $code = AuthorizationCode::generate();
        self::codes()->save(self::code($code, self::client(), $session, null));
        self::reload();
        $record = self::codes()->findByCodeHash(AuthorizationCode::hash($code)) ?? static::fail('The code was not stored.');

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
        $code = AuthorizationCode::generate();
        self::codes()->save(self::code($code, $client, $session, $claims));
        self::reload();

        // When
        $found = self::codes()->findByCodeHash(AuthorizationCode::hash($code)) ?? static::fail('The code was not stored.');

        // Then
        static::assertSame(AuthorizationCode::hash($code), $found->codeHash);
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertSame('oidc-demo', $found->clientId);
        static::assertSame('oidc-demo', $found->client->clientId);
        static::assertTrue($found->session->id->equals($session->id));
        static::assertSame((string) $client->redirectUris[0], (string) $found->redirectUri);
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

    #[Test]
    public function aConsumedCodeStaysConsumed(): void
    {
        // Given
        $code = AuthorizationCode::generate();
        $record = self::code($code, self::client(), self::session(self::user()), null);
        self::codes()->save($record);
        $record->consume(self::now()->modify('+90 seconds'));
        self::codes()->save($record);
        self::reload();

        // When
        $found = self::codes()->findByCodeHash(AuthorizationCode::hash($code)) ?? static::fail('The code was not stored.');

        // Then
        static::assertTrue($found->isUsed());
        static::assertEquals(self::now()->modify('+90 seconds'), $found->usedAt);
    }

    #[Test]
    public function anUnknownCodeIsNotFound(): void
    {
        // When / Then
        static::assertNull(self::codes()->findByCodeHash(AuthorizationCode::hash(AuthorizationCode::generate())));
    }

    /**
     * A code of a client removed from the configuration is an unknown code, which is what the grant
     * refuses.
     */
    #[Test]
    public function aCodeOfAnUnregisteredClientIsNotFound(): void
    {
        // Given
        $ghost = new Client(self::tenant(), 'ghost', 'Removed client', Methods::none(), null, [new RedirectUri('https://ghost.example/callback')]);
        $code = AuthorizationCode::generate();
        self::codes()->save(self::code($code, $ghost, self::session(self::user()), null));
        self::reload();

        // When / Then
        static::assertNull(self::codes()->findByCodeHash(AuthorizationCode::hash($code)));
    }

    /**
     * Back-Channel Logout 1.0 §2.6: the clients that hold a token of the session, each once; a code still
     * waiting at the token endpoint names nobody.
     */
    #[Test]
    public function theClientsOfASessionAreThoseThatExchangedACodeInIt(): void
    {
        // Given
        $session = self::session(self::user());
        self::used($session, self::client(), 'first-of-the-demo');
        self::used($session, self::client(), 'second-of-the-demo');
        self::used($session, self::client('legacy-app'), 'of-the-legacy-app');
        self::codes()->save(self::code(AuthorizationCode::generate(), self::client('native-app'), $session, null));
        self::reload();

        // When
        $clients = array_map(static fn (Client $client): string => $client->clientId, self::loggedInClients()->ofSession($session->id));

        // Then
        sort($clients);
        static::assertSame(['legacy-app', 'oidc-demo'], $clients);
    }

    /**
     * Another browser of the same user keeps its clients: the question is about one session.
     */
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

    /**
     * A client removed from the configuration names nobody to tell of a logout, as it names nobody at the
     * token endpoint.
     */
    #[Test]
    public function aClientNoLongerRegisteredIsNotListed(): void
    {
        // Given
        $session = self::session(self::user());
        $ghost = new Client(self::tenant(), 'ghost', 'Removed client', Methods::none(), null, [new RedirectUri('https://ghost.example/callback')]);
        self::used($session, $ghost, 'of-the-ghost');
        self::reload();

        // When / Then
        static::assertSame([], self::loggedInClients()->ofSession($session->id));
    }

    /**
     * A code the client exchanged for tokens.
     */
    private static function used(AuthenticationSession $session, Client $client, string $code): void
    {
        $record = self::code($code, $client, $session, null);
        $record->consume(self::now()->modify('+90 seconds'));
        self::codes()->save($record);
    }

    private static function loggedInClients(): LoggedInClientsInterface
    {
        return self::service('test.heidi.logged_in_clients', LoggedInClientsInterface::class);
    }

    private static function code(string $code, Client $client, AuthenticationSession $session, ?ClaimsRequest $claims): AuthorizationCode
    {
        return new AuthorizationCode(
            AuthorizationCode::hash($code),
            Uuid::v7(),
            $client,
            $session,
            $client->redirectUris[0],
            new Scopes([new Scope('openid'), new Scope('email')]),
            'n-0S6_WzA2Mj',
            new CodeChallenge(self::CHALLENGE, CodeChallengeMethod::S256),
            null,
            $claims,
            AuthenticationSnapshot::ofSession($session, $session->authenticationContextClass()),
            self::now()->modify('+1 minute'),
            self::now()->modify('+2 minutes'),
        );
    }

    private static function codes(): AuthorizationCodeRepositoryInterface
    {
        return self::service('test.heidi.authorization_codes', AuthorizationCodeRepositoryInterface::class);
    }
}
