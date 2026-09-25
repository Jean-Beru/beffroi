<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Resource;

use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * One resource a client asks a token for (RFC 8707 §2): an absolute URI of RFC 3986 §4.3, without a
 * fragment component.
 */
final class ResourceIndicatorTest extends TestCase
{
    /**
     * RFC 8707 §2: an identifier, which may be a locator; a query component is allowed, the section
     * recognising that it is sometimes what scopes the request.
     */
    #[Test]
    #[DataProvider('provideAbsoluteUris')]
    public function itKeepsAnAbsoluteUriAsItIsWritten(string $value): void
    {
        // When / Then
        static::assertSame($value, new ResourceIndicator($value)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAbsoluteUris(): iterable
    {
        yield 'an https URL' => ['https://api.example.com/'];
        yield 'a path under a host' => ['https://api.example.com/app/'];
        yield 'a query that scopes the request' => ['https://api.example.com/app/?tenant=acme'];
        yield 'a URN' => ['urn:example:cooperation-context'];
        yield 'a host without a path' => ['https://api.example.com'];
    }

    #[Test]
    #[DataProvider('provideFragments')]
    public function itRefusesAFragmentComponent(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('must not carry a fragment component (RFC 8707 section 2)');

        // When
        new ResourceIndicator($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideFragments(): iterable
    {
        yield 'a fragment' => ['https://api.example.com/#today'];
        yield 'an empty fragment' => ['https://api.example.com/#'];
    }

    #[Test]
    #[DataProvider('provideValuesThatAreNotAbsoluteUris')]
    public function itRefusesWhatIsNotAnAbsoluteUri(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not an absolute URI (RFC 8707 section 2, RFC 3986 section 4.3)');

        // When
        new ResourceIndicator($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValuesThatAreNotAbsoluteUris(): iterable
    {
        yield 'empty' => [''];
        yield 'a relative path' => ['/app/'];
        yield 'a network-path reference' => ['//api.example.com/'];
        yield 'a host without a scheme' => ['api.example.com'];
        yield 'a scheme without a hierarchical part' => ['https:'];
        yield 'a scheme starting with a digit' => ['1https://api.example.com/'];
        yield 'a space' => ['https://api.example.com/a b'];
        yield 'a control character' => ["https://api.example.com/\n"];
    }

    /**
     * Compared byte for byte, as every other URI a client registers is.
     *
     * @param bool $equal whether the two name the same resource
     */
    #[Test]
    #[DataProvider('provideComparisons')]
    public function itComparesItselfByteForByte(string $one, string $other, bool $equal): void
    {
        // When / Then
        static::assertSame($equal, new ResourceIndicator($one)->equals(new ResourceIndicator($other)));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function provideComparisons(): iterable
    {
        yield 'the same value' => ['https://api.example.com/', 'https://api.example.com/', true];
        yield 'a trailing slash' => ['https://api.example.com/', 'https://api.example.com', false];
        yield 'another case' => ['https://api.example.com/', 'https://API.example.com/', false];
        yield 'another path' => ['https://api.example.com/app/', 'https://api.example.com/other/', false];
    }

    #[Test]
    public function itWritesItselfAsItsValue(): void
    {
        // When / Then
        static::assertSame('https://api.example.com/', (string) new ResourceIndicator('https://api.example.com/'));
    }
}
