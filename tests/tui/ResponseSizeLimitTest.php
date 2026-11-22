<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests;

use Beffroi\Tui\ResponseSizeLimit;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;

/**
 * An answer is read up to a limit and cut beyond it, rather than held in memory until PHP stops.
 */
final class ResponseSizeLimitTest extends TestCase
{
    #[Test]
    public function anAnswerLargerThanTheLimitIsCut(): void
    {
        // Given
        $http = new MockHttpClient(new MockResponse(str_repeat('a', 2048)));
        $response = $http->request('GET', 'https://op.example/jwks', ['on_progress' => new ResponseSizeLimit(1024)]);

        // Then
        $this->expectException(TransportExceptionInterface::class);
        $this->expectExceptionMessageIs('The answer is larger than the 1024 octets this program reads of one.');

        // When
        $response->getContent();
    }

    #[Test]
    public function anAnswerWithinTheLimitIsRead(): void
    {
        // Given
        $http = new MockHttpClient(new MockResponse(str_repeat('a', 1024)));

        // When
        $content = $http->request('GET', 'https://op.example/jwks', ['on_progress' => new ResponseSizeLimit(1024)])->getContent();

        // Then
        static::assertSame(str_repeat('a', 1024), $content);
    }
}
