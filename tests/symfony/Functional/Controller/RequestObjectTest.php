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
 * RFC 9101 §6.1, OIDC Core §6, Decision 0006
 */
final class RequestObjectTest extends BrowserTestCase
{
    /**
     * RFC 7515 appendix A.3
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
     * RFC 9101 §5.2
     */
    private string $published = '';

    protected function configureContainer(): Closure
    {
        return function (ContainerInterface $container): void {
            $container->set('http_client', new MockHttpClient(fn (): MockResponse => new MockResponse($this->published)));
        };
    }

    /**
     * RFC 9101 §6.1
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
     * OIDC Core §6.1
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
     * OIDC Core §6.1, RFC 7636 §4.3
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
     * RFC 9101 §6.2
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
     * RFC 6749 §5.2
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
     * RFC 9101 §4, RFC 6749 §3.1
     */
    #[Test]
    public function aClaimNamedByANumberIsIgnoredAndTheFlowStarts(): void
    {
        // Given
        // An array would turn "123" into an integer key, so the claims are written from an object.
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
     * Decision 0006
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
     * Decision 0006
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
     * OIDC Discovery §3
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
     * OIDC Core §6
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
     * OIDC Core §6.2
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
     * Architecture §3.3
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
     * RFC 9101 §4
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
     * RFC 7515 §7.1
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
     * RFC 7515 §4.1.1, RFC 7518 §3.6
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
