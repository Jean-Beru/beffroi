<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Registration;

use function str_repeat;
use PHPUnit\Framework\Attributes\DataProvider;
use Beffroi\Core\Tests\Fixture\TextsThatAreNotPlain;
use DateTimeImmutable;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §1.2, Decision 0009
 */
final class InitialAccessTokenTest extends TestCase
{
    #[Test]
    public function aTokenIsKeptAsTheDigestOfItsValue(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token is stored as the hex SHA-256 of its value, never as the value.');

        // When
        self::token(digest: Secrets::draw());
    }

    #[Test]
    public function aTokenCarriesTheNameTheTenantGaveIt(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token carries the name the tenant gave it (RFC 7591 section 1.2).');

        // When
        self::token(name: '');
    }

    #[Test]
    public function aTokenIsWorthAtLeastOneRegistration(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token is worth at least one registration; a token worth none is a token not issued.');

        // When
        self::token(registrationsAllowed: 0);
    }

    #[Test]
    public function aTokenExpiresAfterItWasIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token expires after it was issued.');

        // When
        self::token(expiresAt: Fixtures::now());
    }

    #[Test]
    public function aTokenIsSpentByTheRegistrationsItServed(): void
    {
        // Given
        $token = self::token(registrationsAllowed: 2);

        // When
        $token->spend();

        // Then
        static::assertSame(1, $token->registrationsServed);
        static::assertFalse($token->isSpent());
    }

    #[Test]
    public function aTokenWorthOneAuthorisesNothingOnceItHasServedOne(): void
    {
        // Given
        $token = self::token();

        // When
        $token->spend();

        // Then
        static::assertTrue($token->isSpent());
        static::assertFalse($token->authorisesARegistration(Fixtures::now()));
    }

    #[Test]
    public function anExpiredTokenAuthorisesNothing(): void
    {
        // Given
        $token = self::token();

        // When / Then
        static::assertFalse($token->authorisesARegistration(Fixtures::now()->modify('+2 days')));
    }

    #[Test]
    public function aTokenTheTenantTookBackAuthorisesNothing(): void
    {
        // Given
        $token = self::token();

        // When
        $token->revoke(Fixtures::now());

        // Then
        static::assertTrue($token->isRevoked());
        static::assertFalse($token->authorisesARegistration(Fixtures::now()));
    }

    #[Test]
    public function aTokenKeepsTheInstantItWasFirstTakenBack(): void
    {
        // Given
        $token = self::token();
        $token->revoke(Fixtures::now());

        // When
        $token->revoke(Fixtures::now()->modify('+1 hour'));

        // Then
        static::assertEquals(Fixtures::now(), $token->revokedAt);
    }

    #[Test]
    public function aTokenAuthorisesARegistrationWhileItIsWorthOne(): void
    {
        // Given
        $token = self::token();

        // When / Then
        static::assertTrue($token->authorisesARegistration(Fixtures::now()));
    }

    #[Test]
    public function aTokenIsTheOneItsDigestNames(): void
    {
        // Given
        $token = self::token();

        // When / Then
        static::assertFalse($token->matches(DrawnSecret::digestOf('another value')));
    }

    #[Test]
    public function aTokenBelongsToTheTenantThatIssuedIt(): void
    {
        // Given
        $token = self::token();

        // When / Then
        static::assertFalse($token->belongsTo(Fixtures::tenant('other', 'https://id.other.example')));
    }

    #[Test]
    public function aTokenRecordsWhatTheStoreHolds(): void
    {
        // Given
        $token = self::token(registrationsAllowed: 3);

        // When
        $token->recordRegistrationsServed(3);

        // Then
        static::assertTrue($token->isSpent());
    }

    private static function token(
        ?string $digest = null,
        string $name = 'The team that integrates',
        int $registrationsAllowed = 1,
        ?DateTimeImmutable $expiresAt = null,
    ): InitialAccessToken {
        return new InitialAccessToken(
            Uuid::v7(),
            Fixtures::tenant(),
            $digest ?? DrawnSecret::digestOf(Secrets::draw()),
            $name,
            $registrationsAllowed,
            Fixtures::now(),
            $expiresAt ?? Fixtures::now()->modify('+1 day'),
        );
    }

    /**
     * RFC 7591 §1.2
     */
    #[Test]
    #[DataProvider('provideNamesThatAreNotPlainText')]
    public function aTokenIsNamedInPlainText(string $name): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The name of an initial access token is plain text of at most 255 characters, with no control, format or line separator character.');

        // When
        self::token(name: $name);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesThatAreNotPlainText(): iterable
    {
        yield from TextsThatAreNotPlain::around('partners');
        yield 'longer than a line may be' => [str_repeat('a', 256)];
    }
}
