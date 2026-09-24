<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Tenant;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class IssuerTest extends TestCase
{
    /**
     * OIDC Discovery §3: the issuer is a URL using the https scheme.
     */
    #[Test]
    public function itAcceptsAnHttpsIssuer(): void
    {
        // When / Then
        static::assertSame('https://id.acme.example', (string) new Issuer('https://id.acme.example'));
    }

    /**
     * OIDC Discovery §3: the issuer may have a path.
     */
    #[Test]
    public function itAcceptsAnHttpsIssuerWithAPath(): void
    {
        // When
        $issuer = new Issuer('https://id.example/tenants/acme');

        // Then
        static::assertSame('/tenants/acme', $issuer->path);
    }

    /**
     * RFC 6761 §6.3: names under "localhost" resolve to loopback; plain HTTP is accepted there and only there.
     */
    #[Test]
    #[DataProvider('provideLoopbackIssuers')]
    public function itAcceptsPlainHttpOnLoopbackHostsOnly(string $issuer): void
    {
        // When / Then
        static::assertSame($issuer, (string) new Issuer($issuer));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLoopbackIssuers(): iterable
    {
        yield 'localhost' => ['http://localhost:8080'];
        yield 'subdomain of localhost' => ['http://op.localhost'];
        yield 'IPv4 loopback' => ['http://127.0.0.1'];
        yield 'IPv6 loopback' => ['http://[::1]:8080'];
    }

    #[Test]
    #[DataProvider('provideInvalidIssuers')]
    public function itRejectsWhatClientsWouldRefuseOrCompareDifferently(string $issuer, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new Issuer($issuer);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideInvalidIssuers(): iterable
    {
        yield 'http on a public host' => ['http://id.acme.example', 'must use HTTPS'];
        yield 'http on a .test host, not loopback per RFC 6761 §6.2' => ['http://op.test', 'must use HTTPS'];
        yield 'query string' => ['https://id.acme.example?tenant=acme', 'query or a fragment'];
        yield 'fragment' => ['https://id.acme.example#acme', 'query or a fragment'];
        yield 'trailing slash' => ['https://id.acme.example/', 'must not end with a slash'];
        yield 'credentials' => ['https://user:pass@id.acme.example', 'credentials'];
        yield 'password only' => ['https://:pass@id.acme.example', 'credentials'];
        yield 'user only' => ['https://user@id.acme.example', 'credentials'];
        yield 'loopback prefix on a public host' => ['http://127.0.0.1.evil.example', 'must use HTTPS'];
        yield 'loopback suffix on a public host' => ['http://x127.0.0.1', 'must use HTTPS'];
        yield 'relative' => ['/tenants/acme', 'not an absolute URL'];
        yield 'garbage' => ['not a url', 'not an absolute URL'];
    }

    #[Test]
    public function itTrimsSurroundingWhitespaceAndKeepsTheCaseOfTheValue(): void
    {
        // When
        $issuer = new Issuer('  HTTPS://ID.ACME.EXAMPLE/Tenants/Acme ');

        // Then
        static::assertSame('HTTPS://ID.ACME.EXAMPLE/Tenants/Acme', $issuer->value);
        static::assertSame('/Tenants/Acme', $issuer->path);
    }

    #[Test]
    #[DataProvider('provideUppercaseHosts')]
    public function itLowercasesTheHostForItsChecks(string $issuer, string $host): void
    {
        // When / Then
        static::assertSame($host, new Issuer($issuer)->host);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUppercaseHosts(): iterable
    {
        yield 'https' => ['HTTPS://ID.ACME.EXAMPLE/Tenants/Acme', 'id.acme.example'];
        yield 'http on loopback' => ['HTTP://OP.LOCALHOST', 'op.localhost'];
    }

    #[Test]
    public function itEqualsAnIssuerOfTheSameValue(): void
    {
        // When / Then
        static::assertTrue(new Issuer('https://id.acme.example')->equals(new Issuer('https://id.acme.example')));
    }

    #[Test]
    public function itComparesByteForByte(): void
    {
        // When / Then
        static::assertFalse(new Issuer('https://id.acme.example')->equals(new Issuer('https://id.acme.example/acme')));
    }

    /**
     * RFC 6454 §3.2: the scheme, the host and the port, without the path. What a WebAuthn ceremony
     * accepts as an origin, what RFC 8414 §3 hangs its path under, and what a router builds an absolute
     * URL from, all read here so that the three cannot disagree.
     */
    #[Test]
    #[DataProvider('provideOrigins')]
    public function theOriginIsTheIssuerWithoutItsPath(string $issuer, string $origin): void
    {
        // When / Then
        static::assertSame($origin, new Issuer($issuer)->origin());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideOrigins(): iterable
    {
        yield 'a host alone' => ['https://id.acme.example', 'https://id.acme.example'];
        yield 'a host and a path' => ['https://acme.example/id', 'https://acme.example'];
        yield 'a host, a port and a path' => ['https://acme.example:8443/tenants/acme', 'https://acme.example:8443'];
        yield 'a loopback host with a port' => ['http://127.0.0.1:8080', 'http://127.0.0.1:8080'];
    }
}
