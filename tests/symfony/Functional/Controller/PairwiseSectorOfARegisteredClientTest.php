<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\SectorIdentifiersInterface;
use Closure;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §8.1, OIDC Registration §5, CIBA Core §4
 */
final class PairwiseSectorOfARegisteredClientTest extends BrowserTestCase
{
    private const string INITIAL_ACCESS_TOKEN = 'a-value-the-tenant-handed-out';

    private const string SECTOR_DOCUMENT = 'https://pairwise.test/redirect_uris.json';

    /**
     * @var list<string>
     */
    private array $requested = [];

    protected function configureContainer(): Closure
    {
        return function (ContainerInterface $container): void {
            $container->set('http_client', new MockHttpClient(function (string $method, string $url): MockResponse {
                $this->requested[] = $url;

                return new MockResponse('["https://sector-member.test/callback"]');
            }));
        };
    }

    /**
     * @param array<string, mixed> $members
     */
    #[Test]
    #[DataProvider('provideSectorsTheClientDoesNotProve')]
    public function aSectorTheClientDoesNotProveIsRefused(array $members): void
    {
        // Given
        $this->issue();

        // When
        $this->send($members);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_client_metadata', self::json($response)['error'] ?? null);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideSectorsTheClientDoesNotProve(): iterable
    {
        yield 'the host of a jwks_uri a public device client never authenticates with (CIBA Core §4)' => [[
            'grant_types' => ['urn:ietf:params:oauth:grant-type:device_code'],
            'token_endpoint_auth_method' => 'none',
            'jwks_uri' => 'https://launched-pairwise.test/anything-at-all',
        ]];
        yield 'the host of a redirection URI beside the device grant (RFC 8628 §3.4)' => [[
            'redirect_uris' => ['https://launched-pairwise.test/callback'],
            'grant_types' => ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
        ]];
        yield 'the host of a redirection URI beside a login URI on another host (OIDC Core §4)' => [[
            'redirect_uris' => ['https://launched-pairwise.test/callback'],
            'initiate_login_uri' => 'https://attacker.test/start',
        ]];
        yield 'a document that can vouch for no URI of the client (OIDC Registration §5)' => [[
            'grant_types' => ['urn:ietf:params:oauth:grant-type:device_code'],
            'sector_identifier_uri' => self::SECTOR_DOCUMENT,
        ]];
    }

    /**
     * OIDC Registration §5
     */
    #[Test]
    public function aDocumentThatCanVouchForNoUriOfTheClientIsNeverRead(): void
    {
        // Given
        $this->issue();

        // When
        $this->send([
            'grant_types' => ['urn:ietf:params:oauth:grant-type:device_code'],
            'sector_identifier_uri' => self::SECTOR_DOCUMENT,
        ]);

        // Then
        static::assertSame([], $this->requested);
    }

    /**
     * CIBA Core §4, RFC 8628 §3.4
     */
    #[Test]
    public function aDeviceClientThatAuthenticatesWithAKeyIsOfTheSectorOfItsKeys(): void
    {
        // Given
        $this->issue();
        $this->send([
            'grant_types' => ['urn:ietf:params:oauth:grant-type:device_code'],
            'token_endpoint_auth_method' => 'private_key_jwt',
            'jwks_uri' => 'https://device-maker.test/jwks.json',
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        // When
        $sector = self::service('test.beffroi.sector_identifiers', SectorIdentifiersInterface::class)
            ->sectorOf(self::client(self::string(self::json($response)['client_id'] ?? null))->registration);

        // Then
        static::assertSame('device-maker.test', $sector->host);
    }

    private function issue(): void
    {
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
            ->save(new InitialAccessToken(
                Uuid::v7(),
                self::tenant(),
                DrawnSecret::digestOf(self::INITIAL_ACCESS_TOKEN),
                'A partner of the tenant',
                1,
                self::currentSecond(),
                self::currentSecond()->modify('+1 day'),
            ));
        self::reload();
    }

    /**
     * @param array<string, mixed> $members
     */
    private function send(array $members): void
    {
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::INITIAL_ACCESS_TOKEN,
            ],
            content: json_encode(
                $members
                + [
                    'token_endpoint_auth_method' => 'client_secret_basic',
                    'subject_type' => 'pairwise',
                ],
                JSON_THROW_ON_ERROR,
            ),
        );
    }
}
