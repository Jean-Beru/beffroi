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
    public function itAcceptsAnHttpsIssuerWithOrWithoutAPath(): void
    {
        static::assertSame('https://id.acme.example', (string) new Issuer('https://id.acme.example'));
        static::assertSame('/tenants/acme', (new Issuer('https://id.example/tenants/acme'))->path);
    }

    /**
     * RFC 6761 §6.3: names under "localhost" resolve to loopback; plain HTTP is accepted there and only there.
     */
    #[Test]
    #[DataProvider('provideLoopbackIssuers')]
    public function itAcceptsPlainHttpOnLoopbackHostsOnly(string $issuer): void
    {
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
        try {
            new Issuer($issuer);
            static::fail('The issuer should have been rejected.');
        } catch (InvalidArgumentException $exception) {
            static::assertStringContainsString($reason, $exception->getMessage());
        }
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
    public function itTrimsSurroundingWhitespaceAndLowercasesSchemeAndHostForItsChecks(): void
    {
        $issuer = new Issuer('  HTTPS://ID.ACME.EXAMPLE/Tenants/Acme ');

        static::assertSame('HTTPS://ID.ACME.EXAMPLE/Tenants/Acme', $issuer->value);
        static::assertSame('id.acme.example', $issuer->host);
        static::assertSame('/Tenants/Acme', $issuer->path);
        static::assertSame('op.localhost', (new Issuer('HTTP://OP.LOCALHOST'))->host);
    }

    #[Test]
    public function itComparesByteForByte(): void
    {
        static::assertTrue(new Issuer('https://id.acme.example')->equals(new Issuer('https://id.acme.example')));
        static::assertFalse(new Issuer('https://id.acme.example')->equals(new Issuer('https://id.acme.example/acme')));
    }
}
