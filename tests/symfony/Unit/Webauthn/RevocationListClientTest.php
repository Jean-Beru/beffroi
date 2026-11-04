<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Webauthn;

use App\Webauthn\RevocationListClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * Decision 0006, Decision 0035
 */
final class RevocationListClientTest extends TestCase
{
    private const string FIDO_LIST = 'https://mds3.certinfra.fidoalliance.org/crl/MDSCA-1.crl';

    private const string FIDO_LIST_SERVED = 'https://mds3.fido.tools/crl/MDSCA-1.crl';

    #[Test]
    public function aListIsAskedWithoutFollowingARedirect(): void
    {
        // Given
        $requests = [];
        $client = new RevocationListClient(new MockHttpClient(static function (string $method, string $url, array $options) use (&$requests): MockResponse {
            $requests[] = [$method, $url, $options['max_redirects'] ?? null];

            return new MockResponse('list');
        }));

        // When
        $content = $client->request('GET', 'http://crl.globalsign.com/root-r3.crl')->getContent();

        // Then
        static::assertSame('list', $content);
        static::assertSame([['GET', 'http://crl.globalsign.com/root-r3.crl', 0]], $requests);
    }

    #[Test]
    public function theRedirectOfTheTestServiceOfTheFidoAllianceIsFollowedOnceToItsOwnHost(): void
    {
        // Given
        $requests = [];
        $client = new RevocationListClient(new MockHttpClient(static function (string $method, string $url, array $options) use (&$requests): MockResponse {
            $requests[] = [$url, $options['max_redirects'] ?? null];

            return (
                $url === self::FIDO_LIST
                    ? new MockResponse('', [
                        'http_code' => 302,
                        'response_headers' => [
                            'Location' => self::FIDO_LIST_SERVED,
                        ],
                    ])
                    : new MockResponse('list')
            );
        }));

        // When
        $content = $client->request('GET', self::FIDO_LIST)->getContent();

        // Then
        static::assertSame('list', $content);
        static::assertSame([[self::FIDO_LIST, 0], [self::FIDO_LIST_SERVED, 0]], $requests);
    }

    /**
     * @param non-empty-string $location
     */
    #[Test]
    #[DataProvider('provideRedirectsThatAreNotTheOne')]
    public function aRedirectThatIsNotTheOneIsNotFollowed(string $url, string $location): void
    {
        // Given
        $requests = [];
        $client = new RevocationListClient(new MockHttpClient(static function (string $method, string $asked) use (&$requests, $location): MockResponse {
            $requests[] = $asked;

            return new MockResponse('', [
                'http_code' => 302,
                'response_headers' => [
                    'Location' => $location,
                ],
            ]);
        }));

        // When
        $status = $client->request('GET', $url)->getStatusCode();

        // Then
        static::assertSame(302, $status);
        static::assertSame([$url], $requests);
    }

    /**
     * @return iterable<string, array{string, non-empty-string}>
     */
    public static function provideRedirectsThatAreNotTheOne(): iterable
    {
        yield 'a list of another service' => ['https://crl.example/root.crl', self::FIDO_LIST_SERVED];
        yield 'the test service, to another host' => [self::FIDO_LIST, 'https://elsewhere.example/crl/MDSCA-1.crl'];
        yield 'the test service, to its own host in plain HTTP' => [self::FIDO_LIST, 'http://mds3.fido.tools/crl/MDSCA-1.crl'];
    }

    #[Test]
    public function aSecondRedirectIsNotFollowed(): void
    {
        // Given
        $requests = [];
        $client = new RevocationListClient(new MockHttpClient(static function (string $method, string $url) use (&$requests): MockResponse {
            $requests[] = $url;

            return new MockResponse('', [
                'http_code' => 302,
                'response_headers' => [
                    'Location' => $url === self::FIDO_LIST ? self::FIDO_LIST_SERVED : 'https://mds3.fido.tools/crl/again.crl',
                ],
            ]);
        }));

        // When
        $status = $client->request('GET', self::FIDO_LIST)->getStatusCode();

        // Then
        static::assertSame(302, $status);
        static::assertSame([self::FIDO_LIST, self::FIDO_LIST_SERVED], $requests);
    }
}
