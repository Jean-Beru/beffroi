<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Authorization;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function strlen;
use Symfony\Component\Uid\Uuid;

final class AuthorizationCodeTest extends TestCase
{
    private AuthenticationSession $session;

    private Client $client;

    protected function setUp(): void
    {
        $this->session = Fixtures::session();
        $this->client = Clients::public($this->session->tenant);
    }

    /**
     * Architecture §4.4: the code is 256 bits of the CSPRNG in base64url.
     */
    #[Test]
    public function aCodeIs256RandomBitsInBase64url(): void
    {
        // When
        $code = AuthorizationCode::generate();

        // Then
        static::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $code));
        static::assertNotSame($code, AuthorizationCode::generate());
    }

    /**
     * Architecture §4.4: the code is stored as its SHA-256.
     */
    #[Test]
    public function aCodeIsHashedWithSha256(): void
    {
        // When / Then
        static::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', AuthorizationCode::hash(''));
        static::assertSame(64, strlen(AuthorizationCode::hash(AuthorizationCode::generate())));
    }

    #[Test]
    public function twoCodesHashDifferently(): void
    {
        // Given
        $code = AuthorizationCode::generate();
        $again = AuthorizationCode::generate();

        // When / Then
        static::assertSame(AuthorizationCode::hash($code), AuthorizationCode::hash($code));
        static::assertNotSame(AuthorizationCode::hash($code), AuthorizationCode::hash($again));
    }

    /**
     * Architecture §4.4: everything the token endpoint needs, with the authentication as it was when
     * the code was issued.
     */
    #[Test]
    public function itRecordsWhatTheGrantWillNeed(): void
    {
        // Given
        $issuedAt = Fixtures::now()->modify('+5 minutes');
        $this->session->recordProof(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::context($issuedAt));

        // When
        $code = $this->code($issuedAt, $issuedAt->modify('+60 seconds'));

        // Then
        static::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', $code->codeHash);
        static::assertSame($this->client, $code->client);
        static::assertSame($this->client->registration->clientId, $code->clientId);
        static::assertSame($this->client->tenant, $code->tenant);
        static::assertSame($this->session, $code->session);
        static::assertSame('https://spa.example/callback', (string) $code->redirectUri);
        static::assertEquals([new Scope('openid')], $code->scopes->all);
        static::assertSame('n-0S6_WzA2Mj', $code->nonce);
        static::assertSame(Requests::CHALLENGE, $code->codeChallenge?->value);
        static::assertNull($code->claimsRequest);
        static::assertEquals($issuedAt, $code->authentication->authenticatedAt);
        static::assertSame(['pwd', 'otp', 'mfa'], $code->authentication->methods);
        static::assertSame('2', $code->authentication->contextClass);
        static::assertEquals($issuedAt, $code->issuedAt);
        static::assertEquals($issuedAt->modify('+60 seconds'), $code->expiresAt);
    }

    #[Test]
    public function itRefusesAValueThatIsNotAHexSha256(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'), codeHash: AuthorizationCode::generate());
    }

    #[Test]
    public function itRefusesASessionOfAnotherTenant(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new AuthorizationCode(
            AuthorizationCode::hash(''),
            Uuid::v7(),
            $client,
            $this->session,
            $client->registration->redirectUris[0],
            new Scopes([new Scope('openid')]),
            null,
            null,
            new CodeChallenge(Requests::CHALLENGE, CodeChallengeMethod::S256),
            null,
            null,
            new AuthenticationSnapshot(Fixtures::now(), ['pwd'], '1'),
            Fixtures::now(),
            Fixtures::now()->modify('+60 seconds'),
        );
    }

    #[Test]
    public function itRefusesAnEmptyScopeList(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'), scopes: []);
    }

    #[Test]
    public function itRefusesToExpireBeforeItWasIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $this->code(Fixtures::now(), Fixtures::now());
    }

    #[Test]
    public function aNewCodeIsUnused(): void
    {
        // When
        $code = $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'));

        // Then
        static::assertFalse($code->isUsed());
        static::assertNull($code->usedAt);
    }

    /**
     * RFC 6749 §4.1.2: a code is used once. The first presentation consumes it.
     */
    #[Test]
    public function consumingDatesTheUse(): void
    {
        // Given
        $code = $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'));
        $presentedAt = Fixtures::now()->modify('+2 seconds');

        // When
        $code->consume($presentedAt);

        // Then
        static::assertTrue($code->isUsed());
        static::assertEquals($presentedAt, $code->usedAt);
    }

    /**
     * RFC 6749 §4.1.2: a second presentation is the grant's decision, so consuming twice is a programming error.
     */
    #[Test]
    public function itCannotBeConsumedTwice(): void
    {
        // Given
        $code = $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'));
        $code->consume(Fixtures::now()->modify('+2 seconds'));

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIsOrContains('isUsed()');

        // When
        $code->consume(Fixtures::now()->modify('+3 seconds'));
    }

    #[Test]
    public function aRefusedSecondConsumptionKeepsTheFirstDate(): void
    {
        // Given
        $code = $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'));
        $presentedAt = Fixtures::now()->modify('+2 seconds');
        $code->consume($presentedAt);

        // When
        try {
            $code->consume($presentedAt->modify('+1 second'));
        } catch (LogicException) {
        }

        // Then
        static::assertEquals($presentedAt, $code->usedAt);
    }

    #[Test]
    public function aNewCodeIsNotRevoked(): void
    {
        // When
        $code = $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'));

        // Then
        static::assertFalse($code->isRevoked());
        static::assertNull($code->revokedAt);
    }

    /**
     * RFC 6749 §4.1.2: the replay of a code revokes what was issued from it, said on the grant itself.
     */
    #[Test]
    public function revokingDatesTheRevocation(): void
    {
        // Given
        $code = $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'));
        $replayedAt = Fixtures::now()->modify('+3 seconds');

        // When
        $code->revoke($replayedAt);

        // Then
        static::assertTrue($code->isRevoked());
        static::assertEquals($replayedAt, $code->revokedAt);
    }

    /**
     * A third presentation replays the code again; the grant was revoked when it first was.
     */
    #[Test]
    public function aSecondRevocationKeepsTheFirstDate(): void
    {
        // Given
        $code = $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'));
        $replayedAt = Fixtures::now()->modify('+3 seconds');
        $code->revoke($replayedAt);

        // When
        $code->revoke($replayedAt->modify('+1 second'));

        // Then
        static::assertEquals($replayedAt, $code->revokedAt);
    }

    /**
     * Architecture §4.4: sixty seconds, the last one excluded.
     */
    #[Test]
    #[DataProvider('provideInstants')]
    public function itExpiresAtTheEndOfItsLifetime(string $offset, bool $expired): void
    {
        // Given
        $code = $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'));

        // When / Then
        static::assertSame($expired, $code->isExpired(Fixtures::now()->modify($offset)));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideInstants(): iterable
    {
        yield 'at issuance' => ['+0 seconds', false];
        yield 'last second' => ['+59 seconds', false];
        yield 'at expiry' => ['+60 seconds', true];
        yield 'long after' => ['+1 day', true];
    }

    /**
     * @param list<Scope> $scopes
     */
    private function code(
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiresAt,
        string $codeHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        array $scopes = [new Scope('openid')],
    ): AuthorizationCode {
        return new AuthorizationCode(
            $codeHash,
            Uuid::v7(),
            $this->client,
            $this->session,
            $this->client->registration->redirectUris[0],
            new Scopes($scopes),
            null,
            'n-0S6_WzA2Mj',
            new CodeChallenge(Requests::CHALLENGE, CodeChallengeMethod::S256),
            null,
            null,
            AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
            $issuedAt,
            $expiresAt,
        );
    }
}
