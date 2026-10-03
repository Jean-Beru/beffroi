<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Tenant;

use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #449: where the logo of a tenant is served from, read once and answered.
 */
final class LogoUriTest extends TestCase
{
    #[Test]
    public function itKeepsTheUrlItWasGiven(): void
    {
        // When / Then
        static::assertSame('https://acme.example/logo.svg', new LogoUri('https://acme.example/logo.svg')->value);
    }

    /**
     * RFC 6454 §3.2: a source expression of a policy names the scheme, the host and the port, never a
     * path and never a query.
     */
    #[Test]
    #[DataProvider('provideUrls')]
    public function itDerivesTheOriginAPolicyMayName(string $url, string $origin): void
    {
        // When / Then
        static::assertSame($origin, new LogoUri($url)->origin);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUrls(): iterable
    {
        yield 'a path' => ['https://acme.example/assets/logo.svg', 'https://acme.example'];
        yield 'a port' => ['https://acme.example:8443/logo.svg', 'https://acme.example:8443'];
        yield 'a query' => ['https://acme.example/logo?size=64', 'https://acme.example'];
        yield 'a host of its own' => ['https://cdn.acme.example/logo.svg', 'https://cdn.acme.example'];
        yield 'an uppercase host' => ['https://CDN.Acme.Example/logo.svg', 'https://cdn.acme.example'];
        yield 'a loopback host (RFC 6761 §6.3)' => ['http://op.localhost/logo.svg', 'http://op.localhost'];
    }

    #[Test]
    #[DataProvider('provideRefusedUrls')]
    public function itRefusesWhatABrowserMustNotBeHanded(string $url, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($message);

        // When
        new LogoUri($url);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRefusedUrls(): iterable
    {
        yield 'a relative path' => ['/logo.svg', 'is not an absolute URL'];
        yield 'nothing' => ['', 'is not an absolute URL'];
        yield 'a fragment' => ['https://acme.example/logo.svg#mark', 'must not carry a fragment'];
        yield 'credentials' => ['https://user:secret@acme.example/logo.svg', 'must not carry credentials'];
        yield 'plain HTTP off a loopback host' => ['http://acme.example/logo.svg', 'must use HTTPS'];
        yield 'a scheme of its own' => ['data:image/svg+xml;base64,PHN2Zy8+', 'is not an absolute URL'];
    }

    #[Test]
    public function twoOfThemAreTheSameWhenTheUrlIs(): void
    {
        // When / Then
        static::assertTrue(new LogoUri('https://acme.example/logo.svg')->equals(new LogoUri('https://acme.example/logo.svg')));
    }

    #[Test]
    public function twoOfThemDifferWhenTheUrlDoes(): void
    {
        // When / Then
        static::assertFalse(new LogoUri('https://acme.example/logo.svg')->equals(new LogoUri('https://acme.example/mark.svg')));
    }
}
