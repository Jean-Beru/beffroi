<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Trust;

use function array_map;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Trust\TrustedIssuer;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\TrustedIssuers;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A third party whose signature a tenant trusts (RFC 7523 §3): every list of it is closed, and nothing about it
 * is inferred.
 */
final class TrustedIssuerTest extends TestCase
{
    /**
     * RFC 7523 §3: an issuer trusted for one client is not thereby trusted for every client of the tenant.
     */
    #[Test]
    public function itNamesTheClientsThatMayPresentItsAssertions(): void
    {
        // Given
        $issuer = TrustedIssuers::workforce(clients: ['job-runner']);

        // When / Then
        static::assertTrue($issuer->allowsClient('job-runner'));
    }

    #[Test]
    public function itNamesNobodyElse(): void
    {
        // When / Then
        static::assertFalse(TrustedIssuers::workforce(clients: ['job-runner'])->allowsClient('another-runner'));
    }

    /**
     * RFC 7515 §4.1.1: what it signs with is a closed list too.
     */
    #[Test]
    public function itNamesTheAlgorithmsItSignsWith(): void
    {
        // Given
        $issuer = TrustedIssuers::workforce(signingAlgorithms: ['ES256']);

        // When / Then
        static::assertTrue($issuer->signsWith('ES256'));
    }

    #[Test]
    public function itSignsWithNoOtherAlgorithm(): void
    {
        // When / Then
        static::assertFalse(TrustedIssuers::workforce(signingAlgorithms: ['ES256'])->signsWith('RS256'));
    }

    /**
     * The scopes of a response are a subset of what the issuer is trusted for.
     */
    #[Test]
    public function itIsTrustedForTheScopesItWasRegisteredFor(): void
    {
        // Given
        $issuer = TrustedIssuers::workforce(trustedScopes: ['invoices.read', 'invoices.write']);

        // When / Then
        static::assertTrue($issuer->isTrustedFor(self::scopes(['invoices.read'])));
    }

    #[Test]
    public function itIsTrustedForNothingWider(): void
    {
        // When / Then
        static::assertFalse(TrustedIssuers::workforce(trustedScopes: ['invoices.read'])->isTrustedFor(self::scopes(['invoices.read', 'invoices.write'])));
    }

    /**
     * @param list<non-empty-string> $signingAlgorithms
     * @param list<string> $clients
     */
    #[Test]
    #[DataProvider('provideRegistrationsThatDoNotHoldTogether')]
    public function itRefusesARegistrationThatDoesNotHoldTogether(
        string $issuer,
        array $signingAlgorithms,
        array $clients,
        string $provider,
        string $reason,
    ): void {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new TrustedIssuer($issuer, ClientAssertions::publishedKeys(), $signingAlgorithms, $clients, $provider, self::scopes(['invoices.read']));
    }

    /**
     * @return iterable<string, array{string, list<non-empty-string>, list<string>, string, string}>
     */
    public static function provideRegistrationsThatDoNotHoldTogether(): iterable
    {
        yield 'an issuer that is not a URI' => [
            'workforce',
            ['ES256'],
            ['job-runner'],
            'workforce',
            'named by an absolute URI without a fragment',
        ];
        yield 'an issuer with a fragment' => [
            'https://workforce.example.com/#now',
            ['ES256'],
            ['job-runner'],
            'workforce',
            'named by an absolute URI without a fragment',
        ];
        yield 'no algorithm' => [
            TrustedIssuers::ISSUER,
            [],
            ['job-runner'],
            'workforce',
            'signs with at least one algorithm',
        ];
        yield 'no client' => [
            TrustedIssuers::ISSUER,
            ['ES256'],
            [],
            'workforce',
            'names at least one client that may present its assertions',
        ];
        yield 'no source of identities' => [
            TrustedIssuers::ISSUER,
            ['ES256'],
            ['job-runner'],
            '',
            'names the source of the identities its assertions are about',
        ];
    }

    /**
     * @param list<string> $values
     */
    private static function scopes(array $values): Scopes
    {
        return new Scopes(array_map(static fn (string $value): Scope => new Scope($value), $values));
    }
}
