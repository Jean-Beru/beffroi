<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client\Registration;

use DateInterval;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\Registration\InitialAccessTokenIssuance;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInitialAccessTokenRepository;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 7591 §1.2, Decision 0009
 */
final class InitialAccessTokenIssuanceTest extends TestCase
{
    private const string NOW = '2026-09-29T10:00:00+00:00';

    private InMemoryInitialAccessTokenRepository $tokens;

    private InitialAccessTokenIssuance $issuance;

    protected function setUp(): void
    {
        $this->tokens = new InMemoryInitialAccessTokenRepository();
        $this->issuance = new InitialAccessTokenIssuance(Secrets::drawer(), $this->tokens, new MockClock(self::NOW));
    }

    #[Test]
    public function theValueIsOneThisProviderDrew(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, new DateInterval('P30D'));

        // Then
        static::assertTrue(DrawnSecret::isValue($issued->value));
    }

    #[Test]
    public function theRowKeepsTheDigestAndNotTheValue(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, new DateInterval('P30D'));

        // Then
        static::assertSame(DrawnSecret::digestOf($issued->value), $issued->token->digest);
    }

    #[Test]
    public function itIsWorthWhatWasAskedForForAsLongAsWasAskedFor(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 5, new DateInterval('P7D'));

        // Then
        static::assertSame(5, $issued->token->registrationsAllowed);
        static::assertSame(self::NOW, $issued->token->issuedAt->format('c'));
        static::assertSame('2026-10-06T10:00:00+00:00', $issued->token->expiresAt->format('c'));
    }

    #[Test]
    public function theTokenIsFoundByTheTenantItWasIssuedFor(): void
    {
        // Given
        $tenant = Fixtures::tenant();

        // When
        $issued = $this->issuance->issue($tenant, 'The team that integrates', 1, new DateInterval('P30D'));

        // Then
        static::assertSame($issued->token, $this->tokens->findByDigest($tenant, DrawnSecret::digestOf($issued->value)));
    }

    #[Test]
    public function aTokenWorthNoRegistrationIsNotIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token is worth at least one registration; a token worth none is a token not issued.');

        // When
        $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 0, new DateInterval('P30D'));
    }

    #[Test]
    public function aTokenWithNoNameIsNotIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An initial access token carries the name the tenant gave it (RFC 7591 section 1.2).');

        // When
        $this->issuance->issue(Fixtures::tenant(), '', 1, new DateInterval('P30D'));
    }
}
