<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ClientUriTest extends TestCase
{
    /**
     * RFC 6749 §3.1.2, Back-Channel Logout 1.0 §2.2: an absolute URI, which may carry a query component.
     */
    #[Test]
    #[DataProvider('provideAcceptedUris')]
    public function itAcceptsAbsoluteHttpsUrisAndPlainHttpOnLoopbackOnly(string $uri): void
    {
        // When / Then
        static::assertSame($uri, (string) new ClientUri($uri));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAcceptedUris(): iterable
    {
        yield 'https' => ['https://demo.localhost/login/check'];
        yield 'scheme in capitals (RFC 3986 §3.1, kept as registered)' => ['HTTPS://demo.localhost/login/check'];
        yield 'loopback host in capitals' => ['http://LOCALHOST:8000/login/check'];
        yield 'https with a query' => ['https://rp.example/cb?app=1'];
        yield 'https with a port' => ['https://localhost:8443/test/a/heidi/callback'];
        yield 'http on localhost' => ['http://localhost:8000/login/check'];
        yield 'http under localhost' => ['http://rp.localhost/login/check'];
        yield 'http on IPv4 loopback' => ['http://127.0.0.1:8000/cb'];
        yield 'http on IPv6 loopback' => ['http://[::1]:8000/cb'];
    }

    #[Test]
    #[DataProvider('provideRejectedUris')]
    public function itRejectsWhatCannotBeRegistered(string $uri, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new ClientUri($uri);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRejectedUris(): iterable
    {
        yield 'empty' => ['', 'absolute URI'];
        yield 'relative' => ['/login/check', 'absolute URI'];
        yield 'no host' => ['https:///callback', 'absolute URI'];
        yield 'fragment (RFC 6749 §3.1.2)' => ['https://rp.example/cb#frag', 'fragment'];
        yield 'credentials' => ['https://user:pw@rp.example/cb', 'credentials'];
        yield 'user only' => ['https://user@rp.example/cb', 'credentials'];
        yield 'password only' => ['https://:pw@rp.example/cb', 'credentials'];
        yield 'plain http on a public host' => ['http://rp.example/cb', 'HTTPS'];
        yield 'plain http on a host that only starts with localhost' => ['http://localhost.evil.example/cb', 'HTTPS'];
        yield 'custom scheme of a native app (RFC 8252 §7.1, out of scope)' => ['com.example.app:/oauth2redirect', 'absolute URI'];
    }

    #[Test]
    public function itEqualsAUriOfTheSameBytes(): void
    {
        // Given
        $uri = new ClientUri('https://rp.example/cb');

        // When / Then
        static::assertTrue($uri->equals(new ClientUri('https://rp.example/cb')));
        static::assertFalse($uri->equals(new ClientUri('https://rp.example/cb/')));
    }

    /**
     * RFC 3986 §2.1: every value is percent-encoded, and the registered query is kept before them
     * (RFC 6749 §4.1.2 for a response, Front-Channel Logout 1.0 §2 for a logout).
     */
    #[Test]
    #[DataProvider('provideUrisAndParameters')]
    public function itAppendsPercentEncodedParametersAfterTheRegisteredQuery(string $value, string $expected): void
    {
        // When / Then
        static::assertSame($expected, new ClientUri($value)->withParameters([
            'iss' => 'https://id.acme.example',
            'sid' => 'a&b',
        ]));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUrisAndParameters(): iterable
    {
        yield 'no query registered' => ['https://rp.example/logout', 'https://rp.example/logout?iss=https%3A%2F%2Fid.acme.example&sid=a%26b'];
        yield 'a query registered' => ['https://rp.example/logout?app=1', 'https://rp.example/logout?app=1&iss=https%3A%2F%2Fid.acme.example&sid=a%26b'];
    }

    /**
     * RFC 6454 §3.2: the scheme, the host and the port, which a Content-Security-Policy source
     * expression names; never the path nor the query (Form Post Response Mode §2).
     */
    #[Test]
    #[DataProvider('provideOrigins')]
    public function itExposesItsOrigin(string $value, string $origin): void
    {
        // When / Then
        static::assertSame($origin, new ClientUri($value)->origin);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideOrigins(): iterable
    {
        yield 'a path' => ['https://rp.example/login/check', 'https://rp.example'];
        yield 'a port' => ['https://rp.example:8443/cb', 'https://rp.example:8443'];
        yield 'a registered query' => ['https://rp.example/cb?app=1', 'https://rp.example'];
        yield 'a host in capitals' => ['https://RP.example/cb', 'https://rp.example'];
        yield 'a loopback host (RFC 8252 §7.3)' => ['http://127.0.0.1/callback', 'http://127.0.0.1'];
    }
}
