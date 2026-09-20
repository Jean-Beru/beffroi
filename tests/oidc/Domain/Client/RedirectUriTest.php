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
     * What may be registered at all is the rule of ClientUri, which this URI is one use of: a redirect
     * URI that breaks it is refused where it is registered, not where it is used.
     */
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
