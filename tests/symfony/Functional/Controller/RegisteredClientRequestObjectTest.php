<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Closure;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\RequestObjects;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §6.2, RFC 9101 §5.2
 */
final class RegisteredClientRequestObjectTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    /**
     * OIDC Core §6.2
     */
    private const string REQUEST_URI = 'https://registered.test/request.jwt#kFmWcqLPIFIRMByyjGqWvVNRHCiVuIo3yPUL4R0ZmBw';

    /**
     * RFC 9101 §5.2
     */
    private string $published = '';

    protected function configureContainer(): Closure
    {
        return function (ContainerInterface $container): void {
            $container->set('http_client', new MockHttpClient(fn (): MockResponse => new MockResponse($this->published)));
        };
    }

    #[Test]
    public function anObjectSignedUnderTheRegisteredAlgorithmStartsTheFlow(): void
    {
        // Given
        $clientId = $this->register([
            'request_object_signing_alg' => 'RS256',
        ]);
        $now = self::currentSecond();
        $this->published = RequestObjects::signed(
            [
                'nbf' => $now->getTimestamp(),
                'exp' => $now->getTimestamp() + 300,
            ] + self::asTheModuleSendsIt($clientId),
            algorithm: Algorithms::rs256(),
        );

        // When
        $this->authorize($clientId);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertStringStartsWith('/login?', self::string($response->headers->get('Location')));
    }

    /**
     * Decision 0012, RFC 9101 §4
     */
    #[Test]
    public function theSignedObjectOfTheModuleIsRefusedForCarryingNoNbf(): void
    {
        // Given
        $clientId = $this->register([
            'request_object_signing_alg' => 'RS256',
        ]);
        $this->published = RequestObjects::signed(self::asTheModuleSendsIt($clientId), algorithm: Algorithms::rs256());

        // When
        $crawler = $this->authorize($clientId);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame(
            'invalid_request_object: A request object carries an nbf (RFC 9101 section 4).',
            self::refusal($crawler),
        );
    }

    /**
     * Decision 0012
     */
    #[Test]
    public function theUnsignedObjectOfTheModuleIsRefusedForAnAlgorithmItsClientRegisteredNothingFor(): void
    {
        // Given
        $clientId = $this->register();
        $this->published = RequestObjects::unsigned(self::asTheModuleSendsIt($clientId));

        // When
        $crawler = $this->authorize($clientId);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame(
            'invalid_request_object: The request object is not signed with the algorithm the client registered in request_object_signing_alg (OIDC Registration section 2).',
            self::refusal($crawler),
        );
    }

    /**
     * OIDC Core §6.1
     */
    #[Test]
    public function theUnsignedObjectSentByValueIsRefusedBeforeTheRedirectUriOfTheQuery(): void
    {
        // Given
        $clientId = $this->register();

        // When
        $crawler = $this->browser->request('GET', '/authorize', [
            'client_id' => $clientId,
            'redirect_uri' => 'https://registered.test/somewhere-else',
            'request' => RequestObjects::unsigned(self::asTheModuleSendsIt($clientId)),
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame(
            'invalid_request_object: The request object is not signed with the algorithm the client registered in request_object_signing_alg (OIDC Registration section 2).',
            self::refusal($crawler),
        );
    }

    /**
     * OIDC Core §6.2
     */
    private function authorize(string $clientId): Crawler
    {
        return $this->browser->request('GET', '/authorize', [
            'client_id' => $clientId,
            'request_uri' => self::REQUEST_URI,
        ]);
    }

    /**
     * With a challenge the module does not send: this tenant exempts nobody from PKCE (Decision 0017).
     *
     * @return array<string, mixed>
     */
    private static function asTheModuleSendsIt(string $clientId): array
    {
        return [
            'iss' => $clientId,
            'aud' => self::tenant()->issuer->value,
            'client_id' => $clientId,
            'redirect_uri' => self::REDIRECT_URI,
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'state-of-the-client',
            'nonce' => 'nonce-of-the-client',
            'code_challenge' => self::codeChallenge(),
            'code_challenge_method' => 'S256',
        ];
    }

    private static function refusal(Crawler $page): string
    {
        return $page->filter('p[data-description]')->text();
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function register(array $metadata = []): string
    {
        $this->issue();
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::TOKEN,
            ],
            content: json_encode(
                $metadata
                + [
                    'redirect_uris' => [self::REDIRECT_URI],
                    'request_uris' => [self::REQUEST_URI],
                    'token_endpoint_auth_method' => 'private_key_jwt',
                    'scope' => 'openid',
                    'jwks' => [
                        'keys' => ClientAssertions::publishedKeys(Algorithms::rs256())->keys,
                    ],
                ],
                JSON_THROW_ON_ERROR,
            ),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['client_id']);
    }

    private function issue(): void
    {
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
            ->save(new InitialAccessToken(
                Uuid::v7(),
                self::tenant(),
                DrawnSecret::digestOf(self::TOKEN),
                'The team that integrates',
                1,
                self::currentSecond(),
                self::currentSecond()->modify('+1 day'),
            ));
        self::reload();
    }
}
