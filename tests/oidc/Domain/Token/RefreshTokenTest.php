<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Authorization\ClaimRequest;
use Heidi\Oidc\Domain\Authorization\ClaimsRequest;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Token\GrantedAuthorization;
use Heidi\Oidc\Domain\Token\RefreshToken;
use Heidi\Oidc\Domain\Token\RefreshTokenFamily;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Tokens;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function strlen;

final class RefreshTokenTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    private RefreshTokenFamily $family;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
        $this->family = Tokens::family(Fixtures::now());
    }

    /**
     * Architecture §4.6: 256 bits of the CSPRNG in base64url.
     */
    #[Test]
    public function aTokenIs256RandomBitsInBase64url(): void
    {
        // When
        $token = RefreshToken::generate();

        // Then
        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $token));
        static::assertNotSame($token, RefreshToken::generate());
    }

    /**
     * Architecture §4.6: stored as its SHA-256.
     */
    #[Test]
    public function aTokenIsHashedWithSha256(): void
    {
        // When / Then
        static::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', RefreshToken::hash(''));
        static::assertSame(64, strlen(RefreshToken::hash(RefreshToken::generate())));
    }

    #[Test]
    public function twoTokensHashDifferently(): void
    {
        // Given
        $token = RefreshToken::generate();
        $again = RefreshToken::generate();

        // When / Then
        static::assertSame(RefreshToken::hash($token), RefreshToken::hash($token));
        static::assertNotSame(RefreshToken::hash($token), RefreshToken::hash($again));
    }

    /**
     * Architecture §4.6: everything the next refresh needs, with the authentication of the original
     * authorization.
     */
    #[Test]
    public function itRecordsWhatTheNextRefreshWillNeed(): void
    {
        // Given
        $issuedAt = Fixtures::now()->modify('+5 minutes');
        $this->session->recordProof(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::context($issuedAt));
        $claims = new ClaimsRequest([
            'email' => new ClaimRequest(true),
        ]);

        // When
        $token = Tokens::refreshToken('the-token', $this->client, $this->session, $issuedAt, $this->family, ['openid', 'profile'], $claims);

        // Then
        static::assertSame(RefreshToken::hash('the-token'), $token->tokenHash);
        static::assertSame($this->family, $token->family);
        static::assertSame($this->client, $token->client);
        static::assertSame($this->client->clientId, $token->clientId);
        static::assertSame($this->client->tenant, $token->tenant);
        static::assertSame($this->session, $token->session);
        static::assertEquals([new Scope('openid'), new Scope('profile')], $token->scopes);
        static::assertSame($claims, $token->claimsRequest);
        static::assertEquals($issuedAt, $token->authenticatedAt);
        static::assertSame(['pwd', 'otp'], $token->authenticationMethods);
        static::assertNull($token->authenticationContextClass);
        static::assertEquals($issuedAt, $token->issuedAt);
        static::assertEquals($issuedAt->modify('+30 days'), $token->expiresAt);
    }

    #[Test]
    public function aNewTokenIsNeitherRotatedNorRevoked(): void
    {
        // When
        $token = $this->token();

        // Then
        static::assertNull($token->rotatedAt);
        static::assertNull($token->revokedAt);
        static::assertFalse($token->isRotated());
        static::assertFalse($token->isRevoked());
    }

    #[Test]
    public function itKnowsTheScopesItCarries(): void
    {
        // Given
        $token = Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), $this->family, ['openid', 'profile']);

        // When / Then
        static::assertTrue($token->hasScope(new Scope('profile')));
        static::assertFalse($token->hasScope(new Scope('email')));
    }

    /**
     * @param list<Scope> $requested
     */
    #[Test]
    #[DataProvider('provideRequestedScopes')]
    public function itCoversARequestWithinItsScopes(array $requested, bool $covered): void
    {
        // Given
        $token = Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), $this->family, ['openid', 'profile']);

        // When / Then
        static::assertSame($covered, $token->covers($requested));
    }

    /**
     * @return iterable<string, array{list<Scope>, bool}>
     */
    public static function provideRequestedScopes(): iterable
    {
        yield 'all scopes in another order' => [[new Scope('profile'), new Scope('openid')], true];
        yield 'nothing' => [[], true];
        yield 'a scope it does not carry' => [[new Scope('openid'), new Scope('email')], false];
    }

    #[Test]
    public function itIsIssuedFromAnAuthorizationWithTheGrantedScopes(): void
    {
        // Given
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile', 'email']);
        $authorization = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), $this->family, ['openid', 'profile', 'email']), [new Scope('openid')]);

        // When
        $token = RefreshToken::fromAuthorization(RefreshToken::hash('the-token'), $this->family, $authorization, Fixtures::now(), Fixtures::now()->modify('+30 days'));

        // Then
        static::assertEquals($code->scopes, $token->scopes, 'the token keeps what was granted, not what this response narrowed to');
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+30 days'), $token->expiresAt);
    }

    #[Test]
    public function itIsIssuedFromAnAuthorizationWithItsAuthentication(): void
    {
        // Given
        $authorization = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), $this->family, ['openid', 'profile', 'email']), [new Scope('openid')]);

        // When
        $token = RefreshToken::fromAuthorization(RefreshToken::hash('the-token'), $this->family, $authorization, Fixtures::now(), Fixtures::now()->modify('+30 days'));

        // Then
        static::assertSame($authorization->claimsRequest, $token->claimsRequest);
        static::assertEquals($authorization->authenticatedAt, $token->authenticatedAt);
        static::assertSame($authorization->authenticationMethods, $token->authenticationMethods);
        static::assertSame($authorization->authenticationContextClass, $token->authenticationContextClass);
    }

    /**
     * Architecture §4.6: the sliding expiry is capped by the family, so that the ninetieth day is the
     * end whatever the last refresh.
     */
    #[Test]
    public function itNeverOutlivesItsFamily(): void
    {
        // Given
        $authorization = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), $this->family, ['openid', 'profile', 'email']), [new Scope('openid')]);
        $late = Fixtures::now()->modify('+80 days');

        // When
        $token = RefreshToken::fromAuthorization(RefreshToken::hash('the-token'), $this->family, $authorization, $late, $late->modify('+30 days'));

        // Then
        static::assertEquals($this->family->expiresAt, $token->expiresAt);
    }

    #[Test]
    #[DataProvider('provideInstants')]
    public function itExpiresAtTheEndOfItsLifetime(string $offset, bool $expired): void
    {
        // Given
        $token = Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), $this->family);

        // When / Then
        static::assertSame($expired, $token->isExpired(Fixtures::now()->modify($offset)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideInstants(): iterable
    {
        yield 'at issuance' => ['+0 seconds', false];
        yield 'last second' => ['+30 days -1 second', false];
        yield 'at expiry' => ['+30 days', true];
    }

    /**
     * RFC 6749 §6, RFC 9700 §4.13.2: a token is rotated once.
     */
    #[Test]
    public function rotatingDatesTheRotation(): void
    {
        // Given
        $token = $this->token();
        $presentedAt = Fixtures::now()->modify('+1 day');

        // When
        $token->rotate($presentedAt);

        // Then
        static::assertTrue($token->isRotated());
        static::assertEquals($presentedAt, $token->rotatedAt);
        static::assertFalse($token->isRevoked());
    }

    /**
     * A second presentation is the grant's decision, so rotating twice is a programming error.
     */
    #[Test]
    public function itCannotBeRotatedTwice(): void
    {
        // Given
        $token = $this->token();
        $token->rotate(Fixtures::now()->modify('+1 day'));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('isRotated()');

        // When
        $token->rotate(Fixtures::now()->modify('+1 day +1 second'));
    }

    #[Test]
    public function aRefusedSecondRotationKeepsTheFirstDate(): void
    {
        // Given
        $token = $this->token();
        $presentedAt = Fixtures::now()->modify('+1 day');
        $token->rotate($presentedAt);

        // When
        try {
            $token->rotate($presentedAt->modify('+1 second'));
        } catch (LogicException) {
        }

        // Then
        static::assertEquals($presentedAt, $token->rotatedAt);
    }

    /**
     * Rotating a revoked token is a programming error too.
     */
    #[Test]
    public function aRevokedTokenCannotBeRotated(): void
    {
        // Given
        $token = $this->token();
        $token->revoke(Fixtures::now()->modify('+1 day'));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('revoked');

        // When
        $token->rotate(Fixtures::now()->modify('+2 days'));
    }

    #[Test]
    public function aRefusedRotationOfARevokedTokenLeavesItUnrotated(): void
    {
        // Given
        $token = $this->token();
        $token->revoke(Fixtures::now()->modify('+1 day'));

        // When
        try {
            $token->rotate(Fixtures::now()->modify('+2 days'));
        } catch (LogicException) {
        }

        // Then
        static::assertFalse($token->isRotated());
    }

    #[Test]
    public function revokingDatesTheRevocation(): void
    {
        // Given
        $token = $this->token();
        $revokedAt = Fixtures::now()->modify('+1 day');

        // When
        $token->revoke($revokedAt);

        // Then
        static::assertTrue($token->isRevoked());
        static::assertEquals($revokedAt, $token->revokedAt);
    }

    /**
     * The first revocation wins, like a consent or a session.
     */
    #[Test]
    public function theFirstRevocationWins(): void
    {
        // Given
        $token = $this->token();
        $first = Fixtures::now()->modify('+1 day');
        $token->revoke($first);

        // When
        $token->revoke($first->modify('+1 day'));

        // Then
        static::assertEquals($first, $token->revokedAt);
    }

    #[Test]
    public function itRefusesAValueThatIsNotAHexSha256(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(tokenHash: RefreshToken::generate());
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(client: Clients::public(Fixtures::tenant('other', 'https://id.other.example')));
    }

    #[Test]
    public function itRefusesAnEmptyScopeList(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(scopes: []);
    }

    /**
     * RFC 8176: a session always has at least one proof, so a token always has at least one method.
     */
    #[Test]
    public function itRefusesAnEmptyMethodList(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(methods: []);
    }

    #[Test]
    public function itRefusesToBeIssuedBeforeItsFamilyStarted(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(issuedAt: Fixtures::now()->modify('-1 second'));
    }

    #[Test]
    public function itRefusesToExpireBeforeItWasIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(expiresAt: Fixtures::now());
    }

    #[Test]
    public function itRefusesToOutliveItsFamily(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->token(expiresAt: Fixtures::now()->modify('+90 days +1 second'));
    }

    /**
     * @param list<Scope>|null $scopes
     * @param list<string>|null $methods
     */
    private function token(?string $tokenHash = null, ?Client $client = null, ?array $scopes = null, ?array $methods = null, ?DateTimeImmutable $issuedAt = null, ?DateTimeImmutable $expiresAt = null): RefreshToken
    {
        return new RefreshToken(
            $tokenHash ?? RefreshToken::hash('the-token'),
            $this->family,
            $client ?? $this->client,
            $this->session,
            $scopes ?? [Scope::openid()],
            null,
            $this->session->authenticatedAt(),
            $methods ?? $this->session->methodReferences(),
            null,
            $issuedAt ?? Fixtures::now(),
            $expiresAt ?? Fixtures::now()->modify('+30 days'),
        );
    }
}
