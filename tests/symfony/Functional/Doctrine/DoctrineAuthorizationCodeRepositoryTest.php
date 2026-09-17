<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
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
        static::assertEquals([new Scope('openid'), new Scope('email')], $found->scopes);
        static::assertSame('n-0S6_WzA2Mj', $found->nonce);
        static::assertSame(self::CHALLENGE, $found->codeChallenge?->value);
        static::assertTrue($found->codeChallenge->verifies('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'));
        static::assertEquals($claims, $found->claimsRequest);
        static::assertEquals(self::now(), $found->authenticatedAt);
        static::assertSame(['pwd'], $found->authenticationMethods);
        static::assertSame('1', $found->authenticationContextClass);
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
        $ghost = new Client(self::tenant(), 'ghost', 'Removed client', TokenEndpointAuthMethod::None, null, [new RedirectUri('https://ghost.example/callback')]);
        $code = AuthorizationCode::generate();
        self::codes()->save(self::code($code, $ghost, self::session(self::user()), null));
        self::reload();

        // When / Then
        static::assertNull(self::codes()->findByCodeHash(AuthorizationCode::hash($code)));
    }

    private static function code(string $code, Client $client, AuthenticationSession $session, ?ClaimsRequest $claims): AuthorizationCode
    {
        return new AuthorizationCode(
            AuthorizationCode::hash($code),
            Uuid::v7(),
            $client,
            $session,
            $client->redirectUris[0],
            [new Scope('openid'), new Scope('email')],
            'n-0S6_WzA2Mj',
            new CodeChallenge(self::CHALLENGE, CodeChallengeMethod::S256),
            $claims,
            $session->authenticatedAt(),
            $session->methodReferences(),
            $session->authenticationContextClass()
                ->value,
            self::now()->modify('+1 minute'),
            self::now()->modify('+2 minutes'),
        );
    }

    private static function codes(): AuthorizationCodeRepositoryInterface
    {
        return self::service('test.heidi.authorization_codes', AuthorizationCodeRepositoryInterface::class);
    }
}
