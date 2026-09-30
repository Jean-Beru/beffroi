<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Closure;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\RequestObjects;
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
 * OIDC Core §6.2, RFC 9101 §5.2: a client that registered itself publishes its request object at a URL it
 * registered, and the authorization endpoint reads it back. It is what the two modules of the Dynamic OP
 * plan that play an object by reference do, `oidcc-request-uri-unsigned` with an unsigned object and
 * `oidcc-request-uri-signed-rs256` with one signed under the algorithm it registered, and both must
 * complete the authorization.
 *
 * A run names neither refusal: an object that is refused is an object that was not read, so the answer is
 * a page and never a redirection (`RequestObjectResolver::resolve()`), the scripted browser of the suite
 * waits for a callback that never comes, and what the provider answered is in no artefact of the run
 * (issue #385). Here it is, one test per module: the page carries the code of the refusal and the
 * description that names its rule.
 *
 * The client of each test is registered through the endpoint, as the suite registers its own, with the
 * keys and the `request_uris` of the module. What it publishes behind that URL is answered by a mock, so
 * that what is seen is the endpoint and nothing of the network.
 */
final class RegisteredClientRequestObjectTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    /**
     * OIDC Core §6.2: the URL the client registers carries the hash of what it publishes there, which is
     * what `CreateRandomRequestUriWithFragment` gives both modules (issue #376). What is registered and
     * what a request names is this whole string; what the provider reads is the URL without the fragment.
     */
    private const string REQUEST_URI = 'https://registered.test/request.jwt#kFmWcqLPIFIRMByyjGqWvVNRHCiVuIo3yPUL4R0ZmBw';

    /**
     * What the client publishes behind the `request_uri` it registered, which the provider reads back with
     * one GET (RFC 9101 §5.2).
     */
    private string $published = '';

    protected function configureContainer(): Closure
    {
        return function (ContainerInterface $container): void {
            $container->set('http_client', new MockHttpClient(fn (): MockResponse => new MockResponse($this->published)));
        };
    }

    /**
     * The whole way of `oidcc-request-uri-signed-rs256` when the object carries what a signature is bounded
     * by: registered with `request_object_signing_alg: RS256` and an inline JWK Set, the object published
     * behind the registered URL, read back from it, verified against the key the client published, and the
     * flow started. Nothing of the registration, of the reading back or of the RS256 verification is what
     * the module fails on.
     */
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
     * The object of `oidcc-request-uri-signed-rs256` as the suite builds it, read in the source of the
     * suite at the tag `compose.yaml` pins: the parameters of the authorization request
     * (`ConvertAuthorizationEndpointRequestToRequestObject`), then `aud` and `iss`
     * (`AddAudToRequestObject`, `AddIssToRequestObject`), then the signature. RFC 9101 §4 asks no more of
     * it, `iss` and `aud` being a SHOULD and neither `exp` nor `nbf` being named at all.
     *
     * Decision 0012 asks for the four: they bound what a signature proves, FAPI 2.0 Message Signing
     * requires them, and no exemption on them for a signed object is open to any client. So this is the
     * refusal the module reads as a browser that never reached its callback.
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
     * The object of `oidcc-request-uri-unsigned`, whose registration says nothing about
     * `request_object_signing_alg` and which is serialized with `alg: none`
     * (`SerializeRequestObjectWithNullAlgorithm`). A client that registered nothing is read under any
     * algorithm the provider is wired with and never unsigned (`AnyRegisteredAlgorithm`): decision 0012
     * has an unsigned object registered per client, never fallen into.
     *
     * The module does not skip itself, `skipTestIfNoneUnsupported()` reading
     * `request_object_signing_alg_values_supported`, which carries `none` as soon as one client of the
     * tenant registered it (`AnnouncedRequestObjects`). So this is the refusal it reads.
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
     * OIDC Core §6.2: the request names the client and the URL it published its object at, and nothing
     * else; every parameter of the request is inside the object.
     */
    private function authorize(string $clientId): Crawler
    {
        return $this->browser->request('GET', '/authorize', [
            'client_id' => $clientId,
            'request_uri' => self::REQUEST_URI,
        ]);
    }

    /**
     * The claims the suite signs, which are the parameters of the authorization request plus `iss` and
     * `aud`. The challenge is among them because the tenant of these tests exempts nobody from PKCE where
     * the conformance tenant exempts the confidential clients it registers (decision 0017): what the two
     * modules fail on is not PKCE, and an object that carries no challenge would be refused for that
     * instead.
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

    /**
     * What the page of the refusal says: the code of the protocol and the description that names its rule
     * (`error.html.twig`), which is what no run of the suite reports.
     */
    private static function refusal(Crawler $page): string
    {
        return $page->filter('p[data-description]')->text();
    }

    /**
     * The identifier the provider drew for the client, registered as the modules register theirs: the
     * method that proves a key of its own, the RS256 keys the suite draws and sends inline, and the URL
     * its object is published at.
     *
     * @param array<string, mixed> $metadata what the module adds to the registration request
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
        self::service('test.heidi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
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
