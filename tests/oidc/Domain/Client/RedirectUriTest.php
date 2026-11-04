<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RedirectUriTest extends TestCase
{
    #[Test]
    public function itIsAUriAClientMayRegister(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('fragment');

        // When
        new RedirectUri('https://rp.example/cb#frag');
    }

    #[Test]
    public function itKeepsTheUriAndItsOriginAsRegistered(): void
    {
        // Given
        $uri = new RedirectUri('https://rp.example:8443/cb?app=1');

        // When / Then
        static::assertSame('https://rp.example:8443/cb?app=1', $uri->value);
        static::assertSame('https://rp.example:8443', $uri->origin);
    }

    /**
     * RFC 6749 §3.1.2.3
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

    /**
     * RFC 8252 §8.3
     */
    #[Test]
    #[DataProvider('provideHostsThatAreNotLoopbackLiterals')]
    public function plainHttpOnANameIsNotALoopbackInterface(string $value): void
    {
        // Given
        $uri = new RedirectUri($value);

        // When / Then
        static::assertTrue($uri->isPlainHttpOnAName());
        static::assertFalse($uri->isLoopback());
        static::assertFalse($uri->matchesOnAnyPort($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHostsThatAreNotLoopbackLiterals(): iterable
    {
        yield 'localhost' => ['http://localhost/callback'];
        yield 'localhost with a port' => ['http://localhost:53127/callback'];
        yield 'a name under localhost' => ['http://rp.localhost/callback'];
        yield 'another address of the loopback block' => ['http://127.0.0.2/callback'];
    }

    #[Test]
    #[DataProvider('provideHostsPlainHttpNeverReaches')]
    public function plainHttpElsewhereIsRefusedWhereEveryClientUriIs(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('must use HTTPS; plain HTTP is only accepted on a loopback host');

        // When
        new RedirectUri($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideHostsPlainHttpNeverReaches(): iterable
    {
        yield 'a private address' => ['http://192.168.1.10/callback'];
        yield 'a name' => ['http://rp.example/callback'];
    }

    /**
     * RFC 8252 §7.3
     */
    #[Test]
    #[DataProvider('provideLoopbackLiterals')]
    public function aPlainHttpLoopbackLiteralIsALoopbackInterface(string $value): void
    {
        // Given
        $uri = new RedirectUri($value);

        // When / Then
        static::assertTrue($uri->isLoopback());
        static::assertFalse($uri->isPlainHttpOnAName());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLoopbackLiterals(): iterable
    {
        yield 'IPv4' => ['http://127.0.0.1/callback'];
        yield 'IPv4 with a port' => ['http://127.0.0.1:53127/callback'];
        yield 'IPv6' => ['http://[::1]/callback'];
        yield 'IPv6 with a port' => ['http://[::1]:53127/callback'];
    }

    /**
     * RFC 8252 §7.3
     */
    #[Test]
    #[DataProvider('provideUrisThatAreNotLoopback')]
    public function aUriThatIsNotAPlainHttpLoopbackOneIsNotOne(string $value): void
    {
        // Given
        $uri = new RedirectUri($value);

        // When / Then
        static::assertFalse($uri->isLoopback());
        static::assertFalse($uri->isPlainHttpOnAName());
        static::assertFalse($uri->matchesOnAnyPort($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUrisThatAreNotLoopback(): iterable
    {
        yield 'https on a literal' => ['https://127.0.0.1/callback'];
        yield 'https on a name' => ['https://rp.example/callback'];
        yield 'https on localhost' => ['https://localhost:8443/callback'];
    }

    /**
     * RFC 8252 §7.3
     */
    #[Test]
    #[DataProvider('provideLoopbackCandidates')]
    public function aLoopbackUriMatchesOnAnyPortAndOnNothingElse(string $candidate, bool $matches): void
    {
        // Given
        $uri = new RedirectUri('http://127.0.0.1/callback');

        // When / Then
        static::assertSame($matches, $uri->matchesOnAnyPort($candidate));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideLoopbackCandidates(): iterable
    {
        yield 'the port the operating system handed it' => ['http://127.0.0.1:53127/callback', true];
        yield 'another port' => ['http://127.0.0.1:8080/callback', true];
        yield 'no port at all, as registered' => ['http://127.0.0.1/callback', true];
        yield 'the same with a query as registered' => ['http://127.0.0.1:53127/callback?x=1', false];
        yield 'another path' => ['http://127.0.0.1:53127/other', false];
        yield 'no path' => ['http://127.0.0.1:53127', false];
        yield 'a name in place of the literal' => ['http://localhost:53127/callback', false];
        yield 'the other literal' => ['http://[::1]:53127/callback', false];
        yield 'a private address' => ['http://192.168.1.10/callback', false];
        yield 'HTTPS on the literal' => ['https://127.0.0.1:53127/callback', false];
        yield 'a fragment' => ['http://127.0.0.1:53127/callback#x', false];
        yield 'not a URI at all' => ['/callback', false];
    }

    /**
     * RFC 8252 §7.3
     */
    #[Test]
    public function aLoopbackUriWithAQueryKeepsIt(): void
    {
        // Given
        $uri = new RedirectUri('http://127.0.0.1/callback?app=1');

        // When / Then
        static::assertTrue($uri->matchesOnAnyPort('http://127.0.0.1:53127/callback?app=1'));
        static::assertFalse($uri->matchesOnAnyPort('http://127.0.0.1:53127/callback'));
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
     * RFC 3986 §2.1
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
     * RFC 6749 §3.1.2
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
