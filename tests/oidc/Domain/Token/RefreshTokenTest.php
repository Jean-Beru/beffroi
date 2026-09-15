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
     * Architecture §4.6: 256 bits of the CSPRNG in base64url, stored as its SHA-256.
     */
    #[Test]
    public function aTokenIsRandomAndStoredHashed(): void
    {
        $token = RefreshToken::generate();
        $again = RefreshToken::generate();

        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $token));
        static::assertNotSame($token, $again);
        static::assertSame(64, strlen(RefreshToken::hash($token)));
        static::assertSame(RefreshToken::hash($token), RefreshToken::hash($token));
        static::assertNotSame(RefreshToken::hash($token), RefreshToken::hash($again));
        static::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', RefreshToken::hash(''));
    }

    /**
     * Architecture §4.6: everything the next refresh needs, with the authentication of the original
     * authorization.
     */
    #[Test]
    public function itRecordsWhatTheNextRefreshWillNeed(): void
    {
        $issuedAt = Fixtures::now()->modify('+5 minutes');
        $this->session->recordProof(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::context($issuedAt));
        $claims = new ClaimsRequest([
            'email' => new ClaimRequest(true),
        ]);

        $token = Tokens::refreshToken('the-token', $this->client, $this->session, $issuedAt, $this->family, ['openid', 'profile'], $claims);

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
        static::assertNull($token->rotatedAt);
        static::assertNull($token->revokedAt);
        static::assertFalse($token->isRotated());
        static::assertFalse($token->isRevoked());
        static::assertTrue($token->hasScope(new Scope('profile')));
        static::assertFalse($token->hasScope(new Scope('email')));
        static::assertTrue($token->covers([new Scope('profile'), new Scope('openid')]));
        static::assertTrue($token->covers([]));
        static::assertFalse($token->covers([new Scope('openid'), new Scope('email')]));
    }

    /**
     * Architecture §4.6: the sliding expiry is capped by the family, so that the ninetieth day is the
     * end whatever the last refresh.
     */
    #[Test]
    public function itIsIssuedFromAnAuthorizationWithTheGrantedScopesAndNeverOutlivesItsFamily(): void
    {
        $code = Tokens::code('the-code', $this->client, $this->session, Fixtures::now(), ['openid', 'profile', 'email']);
        $authorization = GrantedAuthorization::fromRefreshToken(Tokens::refreshToken('previous', $this->client, $this->session, Fixtures::now(), $this->family, ['openid', 'profile', 'email']), [new Scope('openid')]);
        $late = Fixtures::now()->modify('+80 days');

        $token = RefreshToken::fromAuthorization(RefreshToken::hash('the-token'), $this->family, $authorization, $late, $late->modify('+30 days'));

        static::assertEquals($code->scopes, $token->scopes, 'the token keeps what was granted, not what this response narrowed to');
        static::assertEquals($this->family->expiresAt, $token->expiresAt);
        static::assertEquals($late, $token->issuedAt);
        static::assertSame($authorization->claimsRequest, $token->claimsRequest);
        static::assertEquals($authorization->authenticatedAt, $token->authenticatedAt);
        static::assertSame($authorization->authenticationMethods, $token->authenticationMethods);
        static::assertSame($authorization->authenticationContextClass, $token->authenticationContextClass);

        $early = RefreshToken::fromAuthorization(RefreshToken::hash('early'), $this->family, $authorization, Fixtures::now(), Fixtures::now()->modify('+30 days'));

        static::assertEquals(Fixtures::now()->modify('+30 days'), $early->expiresAt);
    }

    #[Test]
    public function itExpiresAtTheEndOfItsLifetime(): void
    {
        $token = Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), $this->family);

        static::assertFalse($token->isExpired(Fixtures::now()));
        static::assertFalse($token->isExpired(Fixtures::now()->modify('+30 days -1 second')));
        static::assertTrue($token->isExpired(Fixtures::now()->modify('+30 days')));
    }

    /**
     * RFC 6749 §6, RFC 9700 §4.13.2: a token is rotated once; a second presentation is the grant's
     * decision, so rotating twice, or rotating a revoked token, is a programming error.
     */
    #[Test]
    public function itIsRotatedOnce(): void
    {
        $token = Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), $this->family);
        $presentedAt = Fixtures::now()->modify('+1 day');

        $token->rotate($presentedAt);

        static::assertTrue($token->isRotated());
        static::assertEquals($presentedAt, $token->rotatedAt);
        static::assertFalse($token->isRevoked());

        try {
            $token->rotate($presentedAt->modify('+1 second'));
            static::fail('A token is rotated once.');
        } catch (LogicException $exception) {
            static::assertStringContainsString('isRotated()', $exception->getMessage());
        }
        static::assertEquals($presentedAt, $token->rotatedAt);
    }

    #[Test]
    public function aRevokedTokenIsNotRotated(): void
    {
        $token = Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), $this->family);
        $token->revoke(Fixtures::now()->modify('+1 day'));

        try {
            $token->rotate(Fixtures::now()->modify('+2 days'));
            static::fail('A revoked token is not rotated.');
        } catch (LogicException $exception) {
            static::assertStringContainsString('revoked', $exception->getMessage());
        }
        static::assertFalse($token->isRotated());
    }

    /**
     * The first revocation wins, like a consent or a session.
     */
    #[Test]
    public function theFirstRevocationWins(): void
    {
        $token = Tokens::refreshToken('the-token', $this->client, $this->session, Fixtures::now(), $this->family);
        $first = Fixtures::now()->modify('+1 day');

        static::assertFalse($token->isRevoked());
        $token->revoke($first);
        $token->revoke($first->modify('+1 day'));

        static::assertTrue($token->isRevoked());
        static::assertEquals($first, $token->revokedAt);
    }

    #[Test]
    public function itRefusesAValueThatIsNotAHexSha256(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->token(tokenHash: RefreshToken::generate());
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->token(client: Clients::public(Fixtures::tenant('other', 'https://id.other.example')));
    }

    #[Test]
    public function itRefusesAnEmptyScopeList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->token(scopes: []);
    }

    /**
     * RFC 8176: a session always has at least one proof, so a token always has at least one method.
     */
    #[Test]
    public function itRefusesAnEmptyMethodList(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->token(methods: []);
    }

    #[Test]
    public function itRefusesToBeIssuedBeforeItsFamilyStarted(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->token(issuedAt: Fixtures::now()->modify('-1 second'));
    }

    #[Test]
    public function itRefusesToExpireBeforeItWasIssued(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->token(expiresAt: Fixtures::now());
    }

    #[Test]
    public function itRefusesToOutliveItsFamily(): void
    {
        $this->expectException(InvalidArgumentException::class);
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
