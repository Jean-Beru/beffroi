<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests;

use Beffroi\Tui\LocalhostNames;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * RFC 6761 §6.3: a name under "localhost." is the loopback address, and is asked of no name server.
 */
final class LocalhostNamesTest extends TestCase
{
    /**
     * @param array<string, string> $resolved
     */
    #[Test]
    #[DataProvider('provideNames')]
    public function aNameUnderLocalhostIsTheLoopbackAddress(string $url, array $resolved): void
    {
        // Given
        $options = [];
        $http = new LocalhostNames(new MockHttpClient(static function (string $method, string $url, array $given) use (&$options): MockResponse {
            $options = $given;

            return new MockResponse();
        }));

        // When
        $http->request('GET', $url);

        // Then
        static::assertSame($resolved, $options['resolve'] ?? []);
    }

    /**
     * @return iterable<string, array{string, array<string, string>}>
     */
    public static function provideNames(): iterable
    {
        yield 'a name under localhost' => ['https://op.localhost/.well-known/openid-configuration', ['op.localhost' => '127.0.0.1']];
        yield 'localhost itself' => ['https://localhost:8443/token', ['localhost' => '127.0.0.1']];
        yield 'a name that only ends the same' => ['https://notlocalhost/token', []];
        yield 'any other name' => ['https://op.example/token', []];
    }
}
