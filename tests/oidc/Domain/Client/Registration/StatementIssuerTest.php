<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Registration;

use Beffroi\Oidc\Domain\Client\Registration\StatementIssuer;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7591 §2.3
 */
final class StatementIssuerTest extends TestCase
{
    /**
     * RFC 7515 §4.1.1
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
     * RFC 7519 §4.1.1
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
