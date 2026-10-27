<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Client;

use Beffroi\Bundle\Http\ByteLimit;
use Beffroi\Bundle\Http\Timeout;
use Beffroi\Bundle\Client\ClientJwksFetcher;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Reading back the JWK Set a client publishes (RFC 7591 §2): one GET, bounded, no redirect followed
 * (decision 0006).
 */
final class ClientJwksFetcherTest extends TestCase
{
    private const string JWKS_URI = 'https://key.example/jwks';

    private const int MAX_SIZE = 4096;

    #[Test]
    public function itReadsTheKeysAClientPublishes(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse(json_encode([
            'keys' => [self::key()],
        ], JSON_THROW_ON_ERROR)));

        // When
        $keys = $fetcher->fetch(new ClientUri(self::JWKS_URI));

        // Then
        static::assertSame([self::key()], $keys->keys);
    }

    /**
     * Decision 0006: no outbound request follows a redirect, so a client that moves its keys is told to
     * publish them where it registered them.
     */
    #[Test]
    public function itRefusesToFollowARedirect(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse('', [
            'http_code' => 302,
            'response_headers' => [
                'location' => 'https://elsewhere.example/jwks',
            ],
        ]));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('redirects, and no outbound request follows a redirect');

        // When
        $fetcher->fetch(new ClientUri(self::JWKS_URI));
    }

    #[Test]
    public function itRefusesAnErrorAnswer(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse('nope', [
            'http_code' => 500,
        ]));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('answered 500');

        // When
        $fetcher->fetch(new ClientUri(self::JWKS_URI));
    }

    /**
     * A client that hangs must not hold a worker: an endpoint authenticating it is waiting on this read.
     */
    #[Test]
    public function itRefusesAClientThatDoesNotAnswerInTime(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse('', [
            'error' => 'Idle timeout reached.',
        ]));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('cannot be reached');

        // When
        $fetcher->fetch(new ClientUri(self::JWKS_URI));
    }

    #[Test]
    public function itStopsReadingABodyLongerThanAJwkSetHasReasonToBe(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse(str_repeat('a', self::MAX_SIZE + 1)));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('answers more than 4096 bytes');

        // When
        $fetcher->fetch(new ClientUri(self::JWKS_URI));
    }

    #[Test]
    public function itRefusesAnAnswerThatIsNotJson(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse('<html></html>'));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('does not answer JSON');

        // When
        $fetcher->fetch(new ClientUri(self::JWKS_URI));
    }

    #[Test]
    public function itRefusesAnAnswerThatIsNotAJwkSet(): void
    {
        // Given
        $fetcher = $this->fetcher(new MockResponse(json_encode([
            'nothing' => true,
        ], JSON_THROW_ON_ERROR)));

        // Then
        $this->expectException(ClientKeysUnavailableException::class);
        $this->expectExceptionMessageIsOrContains('does not answer a JWK Set');

        // When
        $fetcher->fetch(new ClientUri(self::JWKS_URI));
    }

    private function fetcher(ResponseInterface $response): ClientJwksFetcher
    {
        return new ClientJwksFetcher(new MockHttpClient($response), new Timeout(1.0), new ByteLimit(self::MAX_SIZE));
    }

    /**
     * @return array<string, mixed>
     */
    private static function key(): array
    {
        return [
            'kty' => 'EC',
            'crv' => 'P-256',
            'kid' => 'one',
            'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
            'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        ];
    }
}
