<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client\Registration;

use Heidi\Oidc\Domain\Client\Registration\StatementIssuer;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §2.3: an authority a tenant pins the software statements of, which is a name, the keys it was
 * pinned by and what it signs with, and nothing inferred.
 */
final class StatementIssuerTest extends TestCase
{
    /**
     * RFC 7515 §4.1.1: what an authority signs with is a closed list, so a key of one kind cannot be used
     * with another.
     */
    #[Test]
    public function itSignsWithWhatItWasPinnedToSignWith(): void
    {
        // Given
        $authority = new StatementIssuer('https://store.example.com', ClientAssertions::publishedKeys(), ['ES256']);

        // When / Then
        static::assertTrue($authority->signsWith('ES256'));
    }

    #[Test]
    public function itDoesNotSignWithAnythingElse(): void
    {
        // Given
        $authority = new StatementIssuer('https://store.example.com', ClientAssertions::publishedKeys(), ['ES256']);

        // When / Then
        static::assertFalse($authority->signsWith('RS256'));
    }

    /**
     * RFC 7519 §4.1.1: an "iss" naming a party whose keys a tenant holds is an absolute URI, compared byte
     * for byte as every other name this provider registers.
     */
    #[Test]
    #[DataProvider('provideNamesThatAreNoIssuer')]
    public function itRefusesANameThatIsNoIssuer(string $issuer): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is named by an absolute URI without a fragment');

        // When
        new StatementIssuer($issuer, ClientAssertions::publishedKeys(), ['ES256']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNamesThatAreNoIssuer(): iterable
    {
        yield 'empty' => [''];
        yield 'no scheme' => ['store.example.com'];
        yield 'with a fragment' => ['https://store.example.com#one'];
        yield 'with a space' => ['https://store.example.com/ one'];
    }

    /**
     * An authority pinned to sign with nothing could sign nothing, so a declaration that names no
     * algorithm is a declaration of nothing.
     */
    #[Test]
    public function itRefusesAnAuthorityThatSignsWithNothing(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('signs with at least one algorithm');

        // When
        new StatementIssuer('https://store.example.com', ClientAssertions::publishedKeys(), []);
    }
}
