<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\BoundedRead;
use App\Http\ByteLimit;
use App\Http\ReadRefusedException;
use App\Http\ReadWords;
use App\Http\Timeout;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;
use Symfony\Component\HttpClient\Exception\TransportException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Decision 0006: a document a third party publishes is read with one GET, no redirect followed, within the timeout
 * and the size its caller is given.
 */
final class BoundedReadTest extends TestCase
{
    private const string URL = 'https://rp.example.com/document';

    private const int LIMIT = 8;

    #[Test]
    public function itReturnsTheBodyOfASuccess(): void
    {
        // When
        $body = self::reading(new MockResponse('document'))->read(self::URL, 'application/json', self::words());

        // Then
        static::assertSame('document', $body);
    }

    #[Test]
    public function itAsksForTheMediaTypeWithOneGetAndFollowsNoRedirect(): void
    {
        // Given
        $response = new MockResponse('{}');

        // When
        self::reading($response)->read(self::URL, 'application/json', self::words());

        // Then
        static::assertSame('GET', $response->getRequestMethod());
        static::assertSame(self::URL, $response->getRequestUrl());
        $headers = $response->getRequestOptions()['headers'];
        static::assertIsArray($headers);
        static::assertContains('Accept: application/json', $headers);
        static::assertSame(0, $response->getRequestOptions()['max_redirects']);
    }

    #[Test]
    public function itGivesTheCallTheTimeoutItWasGiven(): void
    {
        // Given
        $response = new MockResponse('{}');

        // When
        self::reading($response)->read(self::URL, 'application/json', self::words());

        // Then
        static::assertSame(1.5, $response->getRequestOptions()['timeout']);
        static::assertSame(1.5, $response->getRequestOptions()['max_duration']);
    }

    #[Test]
    public function itReadsABodyAsLongAsTheLimit(): void
    {
        // When
        $body = self::reading(new MockResponse(str_repeat('a', self::LIMIT)))->read(self::URL, 'application/json', self::words());

        // Then
        static::assertSame(str_repeat('a', self::LIMIT), $body);
    }

    #[Test]
    public function itStopsAtTheFirstByteBeyondTheLimit(): void
    {
        // Given
        $reading = self::reading(new MockResponse([str_repeat('a', self::LIMIT), 'a']));

        // Then
        $this->expectException(ReadRefusedException::class);
        $this->expectExceptionMessageIs('https://rp.example.com/document answers more than 8 bytes, which no document needs.');

        // When
        $reading->read(self::URL, 'application/json', self::words());
    }

    #[Test]
    #[DataProvider('provideRedirects')]
    public function itRefusesARedirectInTheWordsOfItsCaller(int $status): void
    {
        // Given
        $reading = self::reading(new MockResponse('', [
            'http_code' => $status,
            'response_headers' => [
                'location' => 'https://elsewhere.example/document',
            ],
        ]));

        // Then
        $this->expectException(ReadRefusedException::class);
        $this->expectExceptionMessageIs('https://rp.example.com/document redirects, and no outbound request follows a redirect; publish it where it is registered.');

        // When
        $reading->read(self::URL, 'application/json', self::words());
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideRedirects(): iterable
    {
        yield 'first of the 3xx' => [300];
        yield 'moved permanently' => [301];
        yield 'found' => [302];
        yield 'last of the 3xx' => [399];
    }

    #[Test]
    #[DataProvider('provideStatusesOutsideTheSuccesses')]
    public function itRefusesAnAnswerOutsideTheSuccesses(int $status): void
    {
        // Given
        $reading = self::reading(new MockResponse('', [
            'http_code' => $status,
        ]));

        // Then
        $this->expectException(ReadRefusedException::class);
        $this->expectExceptionMessageIs(sprintf('https://rp.example.com/document answered %d.', $status));

        // When
        $reading->read(self::URL, 'application/json', self::words());
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideStatusesOutsideTheSuccesses(): iterable
    {
        yield 'informational' => [199];
        yield 'not found' => [404];
        yield 'server error' => [500];
    }

    #[Test]
    #[DataProvider('provideSuccesses')]
    public function itAcceptsEveryStatusOfTheSuccesses(int $status): void
    {
        // When
        $body = self::reading(new MockResponse('ok', [
            'http_code' => $status,
        ]))->read(self::URL, 'application/json', self::words());

        // Then
        static::assertSame('ok', $body);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideSuccesses(): iterable
    {
        yield 'ok' => [200];
        yield 'last of the 2xx' => [299];
    }

    #[Test]
    public function itWrapsACallThatFailsAndKeepsItsCause(): void
    {
        // Given
        $reading = new BoundedRead(
            new MockHttpClient(static fn (): MockResponse => throw new TransportException('Could not resolve host.')),
            new Timeout(1.5),
            new ByteLimit(self::LIMIT),
        );

        // When
        try {
            $reading->read(self::URL, 'application/json', self::words());
            static::fail('A call that fails is read.');
        } catch (ReadRefusedException $exception) {
            // Then
            static::assertStringStartsWith('https://rp.example.com/document cannot be reached: ', $exception->getMessage());
            static::assertInstanceOf(TransportException::class, $exception->getPrevious());
        }
    }

    #[Test]
    public function aRefusalCarriesNoCause(): void
    {
        // Given
        $reading = self::reading(new MockResponse('', [
            'http_code' => 404,
        ]));

        // When
        try {
            $reading->read(self::URL, 'application/json', self::words());
            static::fail('An answer of 404 is read.');
        } catch (ReadRefusedException $exception) {
            // Then
            static::assertNull($exception->getPrevious());
        }
    }

    private static function reading(MockResponse $response): BoundedRead
    {
        return new BoundedRead(new MockHttpClient($response), new Timeout(1.5), new ByteLimit(self::LIMIT));
    }

    private static function words(): ReadWords
    {
        return new ReadWords('publish it where it is registered.', '%s answers more than %d bytes, which no document needs.');
    }
}
