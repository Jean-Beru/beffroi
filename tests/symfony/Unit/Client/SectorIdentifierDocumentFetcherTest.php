<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Client;

use Heidi\Bundle\Client\SectorIdentifierDocumentFetcher;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Exception\SectorIdentifierUnavailableException;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Reading back the document a client publishes behind its "sector_identifier_uri" (OIDC Registration §5):
 * one GET, bounded, no redirect followed (decision 0006).
 */
final class SectorIdentifierDocumentFetcherTest extends TestCase
{
    private const string SECTOR_IDENTIFIER_URI = 'https://sector.example/redirect_uris.json';

    private const int MAX_SIZE = 4096;

    #[Test]
    public function itReadsTheRedirectionUrisOfASector(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse(json_encode(
            [
                'https://one.example/cb',
                'https://other.example/cb',
            ],
            JSON_THROW_ON_ERROR,
        )));

        // When
        $redirectUris = $fetcher->fetch(new ClientUri(self::SECTOR_IDENTIFIER_URI));

        // Then
        static::assertSame(['https://one.example/cb', 'https://other.example/cb'], $redirectUris);
    }

    /**
     * Decision 0006: no outbound request follows a redirect. The document is what proves that whoever
     * registers controls the host of the sector, so a third party answering for that host would prove the
     * opposite of what is being asked.
     */
    #[Test]
    public function itRefusesToFollowARedirect(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse('', [
            'http_code' => 302,
            'response_headers' => [
                'location' => 'https://elsewhere.example/redirect_uris.json',
            ],
        ]));

        // Then
        $this->expectException(SectorIdentifierUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('redirects, and no outbound request follows a redirect');

        // When
        $fetcher->fetch(new ClientUri(self::SECTOR_IDENTIFIER_URI));
    }

    #[Test]
    public function itRefusesAnErrorAnswer(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse('nope', [
            'http_code' => 404,
        ]));

        // Then
        $this->expectException(SectorIdentifierUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('answered 404');

        // When
        $fetcher->fetch(new ClientUri(self::SECTOR_IDENTIFIER_URI));
    }

    /**
     * A client that hangs must not hold a worker: a registration is waiting on this read.
     */
    #[Test]
    public function itRefusesAClientThatDoesNotAnswerInTime(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse('', [
            'error' => 'Idle timeout reached.',
        ]));

        // Then
        $this->expectException(SectorIdentifierUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('cannot be reached');

        // When
        $fetcher->fetch(new ClientUri(self::SECTOR_IDENTIFIER_URI));
    }

    #[Test]
    public function itStopsReadingABodyLongerThanAListOfRedirectionUrisHasReasonToBe(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse(str_repeat('a', self::MAX_SIZE + 1)));

        // Then
        $this->expectException(SectorIdentifierUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('answers more than 4096 bytes');

        // When
        $fetcher->fetch(new ClientUri(self::SECTOR_IDENTIFIER_URI));
    }

    #[Test]
    public function itRefusesAnAnswerThatIsNotJson(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse('<html></html>'));

        // Then
        $this->expectException(SectorIdentifierUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('does not answer JSON');

        // When
        $fetcher->fetch(new ClientUri(self::SECTOR_IDENTIFIER_URI));
    }

    /**
     * OIDC Registration §5: a single JSON array, and a registration is refused rather than checked against
     * half a document.
     */
    #[Test]
    public function itRefusesAnAnswerThatIsNotAnArray(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse(json_encode([
            'redirect_uris' => ['https://one.example/cb'],
        ], JSON_THROW_ON_ERROR)));

        // Then
        $this->expectException(SectorIdentifierUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('does not answer the JSON array of redirection URIs');

        // When
        $fetcher->fetch(new ClientUri(self::SECTOR_IDENTIFIER_URI));
    }

    #[Test]
    public function itRefusesAnArrayHoldingSomethingThatIsNoUri(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse(json_encode(
            [
                'https://one.example/cb',
                42,
            ],
            JSON_THROW_ON_ERROR,
        )));

        // Then
        $this->expectException(SectorIdentifierUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('answers an array holding something that is not a redirection URI');

        // When
        $fetcher->fetch(new ClientUri(self::SECTOR_IDENTIFIER_URI));
    }

    private function fetcher(ResponseInterface $response): SectorIdentifierDocumentFetcher
    {
        return new SectorIdentifierDocumentFetcher(new MockHttpClient($response), 1.0, self::MAX_SIZE);
    }
}
