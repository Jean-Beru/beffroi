<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Exchange;

use Beffroi\Oidc\Domain\Exchange\TokenTypeIdentifier;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8693 §3
 */
final class TokenTypeIdentifierTest extends TestCase
{
    /**
     * RFC 8693 §3
     */
    #[Test]
    public function theAccessTokenIsNamedByTheUriOfTheRegistry(): void
    {
        // When / Then
        static::assertSame('urn:ietf:params:oauth:token-type:access_token', TokenTypeIdentifier::accessToken()->value);
    }

    #[Test]
    public function twoIdentifiersAreTheSameWhenTheyReadTheSame(): void
    {
        // When / Then
        static::assertTrue(TokenTypeIdentifier::accessToken()->equals(new TokenTypeIdentifier('urn:ietf:params:oauth:token-type:access_token')));
    }

    #[Test]
    public function twoIdentifiersDifferWhenTheyDoNotReadTheSame(): void
    {
        // When / Then
        static::assertFalse(TokenTypeIdentifier::accessToken()->equals(new TokenTypeIdentifier('urn:ietf:params:oauth:token-type:refresh_token')));
    }

    #[Test]
    public function itReadsAsTheUriItIs(): void
    {
        // When / Then
        static::assertSame('urn:example:token', (string) new TokenTypeIdentifier('urn:example:token'));
    }

    /**
     * RFC 8693 §3, RFC 6755
     */
    #[Test]
    #[DataProvider('provideWhatIsNotAnIdentifier')]
    public function itRefusesWhatIsNotAnAbsoluteUri(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('must be an absolute URI without a fragment (RFC 8693 section 3)');

        // When
        new TokenTypeIdentifier($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNotAnIdentifier(): iterable
    {
        yield 'empty' => [''];
        yield 'a bare word' => ['access_token'];
        yield 'a scheme alone' => ['urn:'];
        yield 'with a fragment' => ['urn:example:token#now'];
        yield 'with a space' => ['urn:example: token'];
        yield 'relative' => ['/token-type/access_token'];
    }
}
