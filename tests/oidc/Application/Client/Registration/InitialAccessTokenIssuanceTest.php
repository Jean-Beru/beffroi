<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client\Registration;

use DateInterval;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\Registration\InitialAccessTokenIssuance;
use Heidi\Oidc\Bridge\InMemory\InMemoryInitialAccessTokenRepository;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * RFC 7591 §1.2, decision 0009: a tenant hands somebody the right to register a client with it.
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

    /**
     * The value is drawn like every other value this provider hands out (DrawnSecret), so what is handed
     * to the team that integrates is of the one shape this provider draws.
     */
    #[Test]
    public function theValueIsOneThisProviderDrew(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, new DateInterval('P30D'));

        // Then
        static::assertTrue(DrawnSecret::isValue($issued->value));
    }

    /**
     * What the row keeps is the digest and never the value, which is what makes a store read by somebody
     * else nothing to present.
     */
    #[Test]
    public function theRowKeepsTheDigestAndNotTheValue(): void
    {
        // When
        $issued = $this->issuance->issue(Fixtures::tenant(), 'The team that integrates', 1, new DateInterval('P30D'));

        // Then
        static::assertSame(DrawnSecret::digestOf($issued->value), $issued->token->digest);
    }

    /**
     * The token is worth what was asked for, for as long as was asked for, counted from one reading of
     * the clock.
     */
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

    /**
     * It is issued for the tenant it was asked for, and the endpoint of another tenant finds nothing.
     */
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

    /**
     * What the record refuses of itself, the issuance refuses: a token worth no registration is a token
     * not issued.
     */
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
