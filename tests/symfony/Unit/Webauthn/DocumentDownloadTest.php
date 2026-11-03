<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Webauthn;

use App\Webauthn\DocumentDownload;
use App\Webauthn\DownloadRefusedException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * What the console downloads for the passkeys: one GET, its answer whole, and no redirect followed (decision 0006).
 */
final class DocumentDownloadTest extends TestCase
{
    #[Test]
    public function theDocumentIsTheAnswerOfOneGetThatFollowsNoRedirect(): void
    {
        // Given
        $requests = [];
        $download = new DocumentDownload(new MockHttpClient(static function (string $method, string $url, array $options) use (&$requests): MockResponse {
            $requests[] = [$method, $url, $options['max_redirects'] ?? null];

            return new MockResponse('{"list": 1}');
        }));

        // When
        $document = $download->of('https://lists.example/aaguid.json');

        // Then
        static::assertSame('{"list": 1}', $document);
        static::assertSame([['GET', 'https://lists.example/aaguid.json', 0]], $requests);
    }

    #[Test]
    public function aRedirectIsRefusedWithTheUrlItLeadsTo(): void
    {
        // Given
        $download = new DocumentDownload(new MockHttpClient([new MockResponse('', [
            'http_code' => 302,
            'response_headers' => [
                'location' => 'https://elsewhere.example/aaguid.json',
            ],
        ])]));

        // Then
        $this->expectException(DownloadRefusedException::class);
        $this->expectExceptionMessageIs('the service redirects to https://elsewhere.example/aaguid.json, and no outbound request follows a redirect; name that URL instead');

        // When
        $download->of('https://lists.example/aaguid.json');
    }

    #[Test]
    #[DataProvider('provideAnswersThatAreNotADocument')]
    public function anAnswerOtherThanOkIsRefusedWithItsStatus(int $status): void
    {
        // Given
        $download = new DocumentDownload(new MockHttpClient([new MockResponse('{}', [
            'http_code' => $status,
        ])]));

        // Then
        $this->expectException(DownloadRefusedException::class);
        $this->expectExceptionMessageIs('the service answered ' . $status);

        // When
        $download->of('https://lists.example/aaguid.json');
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideAnswersThatAreNotADocument(): iterable
    {
        yield 'no content' => [204];
        yield 'not found' => [404];
        yield 'too many requests, which the service of the FIDO Alliance answers a second download in minutes' => [429];
        yield 'a failure of the service' => [503];
    }

    #[Test]
    public function aServiceThatCannotBeReachedIsRefused(): void
    {
        // Given
        $download = new DocumentDownload(new MockHttpClient([new MockResponse('', [
            'error' => 'Could not resolve host: lists.example',
        ])]));

        // Then
        $this->expectException(DownloadRefusedException::class);
        $this->expectExceptionMessageIsOrContains('the service cannot be reached: Could not resolve host: lists.example');

        // When
        $download->of('https://lists.example/aaguid.json');
    }
}
