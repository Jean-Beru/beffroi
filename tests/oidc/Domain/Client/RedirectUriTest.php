<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RedirectUriTest extends TestCase
{
    /**
     * RFC 6749 §3.1.2: an absolute URI, which may carry a query component.
     */
    #[Test]
    #[DataProvider('provideAcceptedUris')]
    public function itAcceptsAbsoluteHttpsUrisAndPlainHttpOnLoopbackOnly(string $uri): void
    {
        // When / Then
        static::assertSame($uri, (string) new RedirectUri($uri));
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
        new RedirectUri($uri);
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

    /**
     * RFC 6749 §3.1.2.3: simple string comparison, so a different case, a trailing slash or a default port
     * spelled out are different URIs.
     */
    #[Test]
    #[DataProvider('provideCandidates')]
    public function itMatchesByteForByte(string $candidate, bool $matches): void
    {
        // Given
        $uri = new RedirectUri('https://rp.example/cb');

        // When / Then
        static::assertSame($matches, $uri->matches($candidate));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideCandidates(): iterable
    {
        yield 'same bytes' => ['https://rp.example/cb', true];
        yield 'trailing slash' => ['https://rp.example/cb/', false];
        yield 'host in capitals' => ['https://RP.example/cb', false];
        yield 'default port spelled out' => ['https://rp.example:443/cb', false];
        yield 'extra query' => ['https://rp.example/cb?x=1', false];
    }

    #[Test]
    public function itEqualsAUriOfTheSameBytes(): void
    {
        // Given
        $uri = new RedirectUri('https://rp.example/cb');

        // When / Then
        static::assertTrue($uri->equals(new RedirectUri('https://rp.example/cb')));
        static::assertFalse($uri->equals(new RedirectUri('https://rp.example/cb/')));
    }

    /**
     * RFC 3986 §2.1: every value is percent-encoded.
     */
    #[Test]
    public function itAppendsPercentEncodedResponseParameters(): void
    {
        // Given
        $uri = new RedirectUri('https://rp.example/cb');

        // When
        $withParameters = $uri->withParameters([
            'code' => 'Splx lOBe',
            'iss' => 'https://id.acme.example',
        ]);

        // Then
        static::assertSame('https://rp.example/cb?code=Splx%20lOBe&iss=https%3A%2F%2Fid.acme.example', $withParameters);
    }

    /**
     * RFC 6749 §3.1.2: the response parameters are added to the query the client registered, which is kept.
     */
    #[Test]
    public function itKeepsTheRegisteredQueryBeforeTheResponseParameters(): void
    {
        // Given
        $uri = new RedirectUri('https://rp.example/cb?app=1');

        // When
        $withParameters = $uri->withParameters([
            'state' => 'a&b',
        ]);

        // Then
        static::assertSame('https://rp.example/cb?app=1&state=a%26b', $withParameters);
    }
}
