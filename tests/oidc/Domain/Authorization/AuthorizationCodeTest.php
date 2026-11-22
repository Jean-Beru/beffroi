<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Authorization;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthenticationSnapshot;
use Beffroi\Oidc\Domain\Authorization\AuthorizationCode;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Exception\LogicException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Requests;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
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
     * Architecture §4.4
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
        $this->code(Fixtures::now(), Fixtures::now()->modify('+60 seconds'), codeHash: Secrets::draw());
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
            DrawnSecret::digestOf(''),
            Uuid::v7(),
            $client,
            $this->session,
            $client->registration->redirectUris[0],
            new Scopes([new Scope('openid')]),
            null,
            null,
            null,
            new CodeChallenge(Requests::CHALLENGE, new Sha256CodeChallengeMethod()),
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
     * RFC 6749 §4.1.2
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
     * RFC 6749 §4.1.2
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
     * RFC 6749 §4.1.2
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
     * Architecture §4.4
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
            null,
            'n-0S6_WzA2Mj',
            new CodeChallenge(Requests::CHALLENGE, new Sha256CodeChallengeMethod()),
            null,
            null,
            AuthenticationSnapshot::ofSession($this->session, $this->session->authenticationContextClass()),
            $issuedAt,
            $expiresAt,
        );
    }
}
