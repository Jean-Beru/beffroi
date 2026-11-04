<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use Beffroi\Oidc\Domain\Client\RequestUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class RequestUriTest extends TestCase
{
    /**
     * OIDC Core §6.2
     */
    #[Test]
    public function itAcceptsTheFragmentOfTheSpecificationAndKeepsIt(): void
    {
        // Given
        $value = 'https://jar.example/request.jwt#ZmFrZS1oYXNoLW9mLXRoZS1jb250ZW50';

        // When / Then
        static::assertSame($value, (string) new RequestUri($value));
    }

    /**
     * RFC 3986 §3.5
     */
    #[Test]
    public function theUrlItIsReadFromCarriesNoFragment(): void
    {
        // Given
        $uri = new RequestUri('https://jar.example/request.jwt?v=2#ZmFrZS1oYXNo');

        // When / Then
        static::assertSame('https://jar.example/request.jwt?v=2', $uri->location->value);
    }

    #[Test]
    public function aUriWithNoFragmentIsReadAsItWasRegistered(): void
    {
        // Given
        $uri = new RequestUri('https://jar.example/request.jwt');

        // When / Then
        static::assertSame('https://jar.example/request.jwt', $uri->location->value);
    }

    #[Test]
    #[DataProvider('provideUrisNoClientMayRegister')]
    public function itIsAUriAClientMayRegister(string $value, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new RequestUri($value);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideUrisNoClientMayRegister(): iterable
    {
        yield 'plain HTTP on a name' => ['http://jar.example/request.jwt#ZmFrZQ', 'must use HTTPS'];
        yield 'credentials' => ['https://user:pass@jar.example/request.jwt', 'must not carry credentials'];
        yield 'no scheme at all' => ['/request.jwt#ZmFrZQ', 'is not an absolute URI'];
        yield 'a fragment and nothing else' => ['#ZmFrZQ', 'is not an absolute URI'];
    }

    #[Test]
    public function itIsComparedByteForByteWithItsFragment(): void
    {
        // Given
        $uri = new RequestUri('https://jar.example/request.jwt#ZmFrZQ');

        // When / Then
        static::assertTrue($uri->equals(new RequestUri('https://jar.example/request.jwt#ZmFrZQ')));
        static::assertFalse($uri->equals(new RequestUri('https://jar.example/request.jwt#YW5vdGhlcg')));
        static::assertFalse($uri->equals(new RequestUri('https://jar.example/request.jwt')));
    }
}
