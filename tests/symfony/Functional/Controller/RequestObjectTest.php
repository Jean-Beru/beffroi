<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_filter;
use function base64_encode;
use Closure;
use DateTimeImmutable;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Token\JwtPayload;
use Beffroi\Oidc\Tests\Fixture\RequestObjects;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use function rtrim;
use function strtr;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 9101 §6.1 and OIDC Core §6, the request the client signs: the authorization endpoint reads the
 * object and not the query, the object of a client that registered "none" is read unsigned, and a
 * "request_uri" is read back only from a URL the client registered (decision 0006).
 *
 * The same object encrypted to the key the tenant publishes (issue #189) is served the same way, by
 * value and by reference, and opens with that key alone: once it has retired, the object is refused.
 * What the client publishes behind its "request_uri" is answered here by a mock, so that what is seen
 * is the endpoint and nothing of the network.
 */
final class RequestObjectTest extends BrowserTestCase
{
    /**
     * The private half of the key "jar-app" publishes in the test kernel: the EC key of RFC 7515
     * appendix A.3, a published test vector that signs nothing outside of this suite.
     */
    private const array PRIVATE_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'kid' => 'jar-key',
        'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
    ];

    /**
     * What the client publishes behind the "request_uri" it registered, which the provider reads back
     * with one GET (RFC 9101 §5.2).
     */
    private string $published = '';

    protected function configureContainer(): Closure
    {
        return function (ContainerInterface $container): void {
            $container->set('http_client', new MockHttpClient(fn (): MockResponse => new MockResponse($this->published)));
        };
    }

    /**
     * RFC 9101 §6.1: a request carried in a JWT starts the flow like any other, the end user being sent
     * to the login page the request object asked for.
     */
    #[Test]
    public function aRequestSignedByItsClientStartsTheFlow(): void
    {
        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request' => $this->signed(self::request()),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?', self::string($response->headers->get('Location')));
    }

    /**
     * OIDC Core §6.1: the parameters of the object are the request, so a scope the object names is the
     * scope of the request and the one of the query is dropped.
     */
    #[Test]
    public function theScopeOfTheObjectIsHonouredAgainstTheQuery(): void
    {
        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'scope' => 'openid profile',
            'request' => $this->signed(self::request([
                'scope' => 'openid banking',
            ])),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('invalid_scope', self::redirectedQuery($response)['error'] ?? null);
    }

    /**
     * OIDC Core §6.1: a parameter of the query the object does not carry is no part of the request; PKCE
     * is required of this client, and an object that carries no challenge carries none whatever the
     * query says (RFC 7636 §4.3).
     */
    #[Test]
    public function aParameterOfTheQueryTheObjectDoesNotCarryIsIgnored(): void
    {
        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'code_challenge' => self::codeChallenge(),
            'code_challenge_method' => 'S256',
            'request' => $this->signed(self::request([
                'code_challenge' => null,
                'code_challenge_method' => null,
            ])),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('invalid_request', self::redirectedQuery($response)['error'] ?? null);
    }

    /**
     * RFC 9101 §6.2: the signature is verified against the keys the client publishes, and an object
     * signed with another key is refused on a page, the request never having been read.
     */
    #[Test]
    public function anObjectSignedWithAnotherKeyIsRefusedOnAPage(): void
    {
        // Given
        $other = new JWK(Algorithms::es256()->generateKey()->all());

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request' => $this->signed(self::request(), $other),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="invalid_request_object"', self::string($response->getContent()));
    }

    /**
     * RFC 6749 §5.2 and issue #837: a value no authorization request carries is refused on a page under
     * a name no error description can hold, and the description the page shows names the rule and
     * nothing the client wrote.
     */
    #[Test]
    public function aValueUnderANameNoDescriptionHoldsIsRefusedOnAPage(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request' => $this->signed([
                ...self::request(),
                'prömpt' => true,
            ]),
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame(
            'invalid_request_object: A claim of the request object holds a value no authorization request carries (OIDC Core section 6.1).',
            $crawler->filter('p[data-description]')->text(),
        );
    }

    /**
     * RFC 9101 §4, RFC 6749 §3.1 and issue #837: a claim named by a number is an extension parameter the
     * provider does not recognise, and the request it travels in starts the flow without it.
     */
    #[Test]
    public function aClaimNamedByANumberIsIgnoredAndTheFlowStarts(): void
    {
        // Given
        // in a PHP array, a member named by a number is an integer key, and the claims signed() takes
        // are named by strings: the payload is written from an object, as a client in another language
        // writes it
        $claims = (object) self::request();
        $claims->{'123'} = 'x';

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request' => $this->signedPayload(json_encode($claims, JSON_THROW_ON_ERROR)),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?', self::string($response->headers->get('Location')));
    }

    /**
     * Decision 0006 and issue #142: the object of the client that registered "none" is read unsigned and
     * asked for none of the claims that bound a proof, which is the object
     * "oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported" sends; the response
     * mode written inside it is the one the answer uses, the module having been waiting for exactly that.
     */
    #[Test]
    public function theResponseModeInsideAnUnsignedObjectIsTheOneTheAnswerUses(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/authorize', [
            'client_id' => 'unsigned-jar-app',
            'redirect_uri' => 'https://unsigned.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'request' => self::unsigned([
                'client_id' => 'unsigned-jar-app',
                'redirect_uri' => 'https://unsigned.test/callback',
                'response_type' => 'code',
                'response_mode' => 'form_post',
                'scope' => 'openid banking',
                'state' => 'state-of-the-client',
                'nonce' => 'nonce-of-the-client',
            ]),
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('https://unsigned.test/callback', $crawler->filter('form')->attr('action'));
        static::assertSame('invalid_scope', self::postedFields($crawler)['error'] ?? null);
        static::assertSame('state-of-the-client', self::postedFields($crawler)['state'] ?? null);
    }

    /**
     * The same object, with a scope the client is allowed: the flow starts and the end user is sent to
     * the login page, which is the branch the module of the Form Post plan takes.
     */
    #[Test]
    public function anUnsignedObjectWithoutRegisteredClaimsStartsTheFlow(): void
    {
        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'unsigned-jar-app',
            'redirect_uri' => 'https://unsigned.test/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'request' => self::unsigned([
                'client_id' => 'unsigned-jar-app',
                'redirect_uri' => 'https://unsigned.test/callback',
                'response_type' => 'code',
                'response_mode' => 'form_post',
                'scope' => 'openid',
                'state' => 'state-of-the-client',
                'nonce' => 'nonce-of-the-client',
                'code_challenge' => self::codeChallenge(),
                'code_challenge_method' => 'S256',
            ]),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?', self::string($response->headers->get('Location')));
    }

    /**
     * Decision 0006: an unsigned object is read from the client that registered it and from no other.
     */
    #[Test]
    public function anUnsignedObjectFromAClientThatRegisteredNothingIsRefused(): void
    {
        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request' => self::unsigned(self::request()),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="invalid_request_object"', self::string($response->getContent()));
    }

    /**
     * OIDC Discovery §3 "require_request_uri_registration": a URL the client did not register is refused
     * on a page, and nothing of the provider goes out to read it.
     */
    #[Test]
    public function aReferenceTheClientDidNotRegisterIsRefused(): void
    {
        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request_uri' => 'https://jar.test/another.jwt',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="invalid_request_uri"', self::string($response->getContent()));
    }

    /**
     * OIDC Core §6: the two ways in are two, and never both at once.
     */
    #[Test]
    public function anObjectSentByValueAndByReferenceAtOnceIsRefused(): void
    {
        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request' => $this->signed(self::request()),
            'request_uri' => 'https://jar.test/request.jwt',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="invalid_request"', self::string($response->getContent()));
    }

    /**
     * The acceptance of issue #189: the same request, encrypted to the key the tenant publishes for
     * encryption, starts the same flow. Nothing of it is readable on the wire, and the signature the
     * client wrote inside is the one that is verified.
     */
    #[Test]
    public function aRequestEncryptedToThePublishedKeyStartsTheFlow(): void
    {
        // Given
        $key = self::encryptionKey();

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request' => RequestObjects::encryptedTo($key->publicJwk, $this->signed(self::request()), [
                'cty' => 'JWT',
            ]),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?', self::string($response->headers->get('Location')));
    }

    /**
     * OIDC Core §6.2: an encrypted object published behind a registered "request_uri" is read back and
     * opened exactly as one sent by value.
     */
    #[Test]
    public function anEncryptedObjectBehindARegisteredReferenceIsReadBack(): void
    {
        // Given
        $key = self::encryptionKey();
        $this->published = RequestObjects::encryptedTo($key->publicJwk, $this->signed(self::request()), [
            'cty' => 'JWT',
        ]);

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request_uri' => 'https://jar.test/request.jwt',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?', self::string($response->headers->get('Location')));
    }

    /**
     * Architecture §3.3: an encryption key opens what was encrypted to it as long as the JWK Set
     * publishes it; past its retirement, the object is refused on a page, the request never having been
     * read.
     */
    #[Test]
    public function anObjectEncryptedToAKeyThatHasRetiredIsRefusedOnAPage(): void
    {
        // Given
        $retired = self::encryptionKey();
        $object = RequestObjects::encryptedTo($retired->publicJwk, $this->signed(self::request()), [
            'cty' => 'JWT',
        ]);
        self::encryptionKey();
        self::retireKey($retired);

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'jar-app',
            'request' => $object,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="invalid_request_object"', self::string($response->getContent()));
    }

    /**
     * RFC 9101 §4: the claims of a request object as a client of this kernel writes them.
     *
     * @param array<string, string|null> $overrides
     *
     * @return array<string, mixed>
     */
    private static function request(array $overrides = []): array
    {
        $now = new DateTimeImmutable();
        $claims = [
            'iss' => 'jar-app',
            'aud' => 'https://op.test',
            'nbf' => $now->getTimestamp(),
            'exp' => $now->getTimestamp() + 300,
            'client_id' => 'jar-app',
            'redirect_uri' => 'https://jar.test/callback',
            'response_type' => 'code',
            'scope' => 'openid profile',
            'state' => 'state-of-the-client',
            'nonce' => 'nonce-of-the-client',
            'code_challenge' => self::codeChallenge(),
            'code_challenge_method' => 'S256',
            ...$overrides,
        ];
        if (($claims['client_id'] ?? null) !== 'jar-app') {
            $claims['iss'] = $claims['client_id'];
        }

        return array_filter($claims, static fn (mixed $value): bool => $value !== null);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function signed(array $claims, ?JWK $key = null): string
    {
        return $this->signedPayload(JwtPayload::encode($claims), $key);
    }

    /**
     * RFC 7515 §7.1: the claims as the client wrote them, signed with the key it publishes unless the
     * test names another.
     */
    private function signedPayload(string $payload, ?JWK $key = null): string
    {
        $jws = new JWSBuilder(new AlgorithmManager([Algorithms::es256()->joseAlgorithm()]))
            ->create()
            ->withPayload($payload)
            ->addSignature($key ?? new JWK(self::PRIVATE_KEY), [
                'alg' => 'ES256',
                'kid' => 'jar-key',
            ])
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }

    /**
     * RFC 7515 §4.1.1, RFC 7518 §3.6: the two segments and the empty signature of an unsecured JWS.
     *
     * @param array<string, mixed> $claims
     */
    private static function unsigned(array $claims): string
    {
        return (
            self::segment(JwtPayload::encode([
                'alg' => 'none',
            ]))
            . '.'
            . self::segment(JwtPayload::encode($claims))
            . '.'
        );
    }

    private static function segment(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /**
     * The hidden fields of the form the page posts.
     *
     * @return array<string, string>
     */
    private static function postedFields(Crawler $page): array
    {
        $fields = [];
        foreach ($page->filter('form input[type=hidden]')->extract(['name', 'value']) as $field) {
            static::assertIsArray($field);
            $fields[self::string($field[0] ?? null)] = self::string($field[1] ?? null);
        }

        return $fields;
    }
}
