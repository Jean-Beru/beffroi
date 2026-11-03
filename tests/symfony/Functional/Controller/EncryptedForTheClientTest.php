<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_map;
use function base64_encode;
use function count;
use function explode;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer as JweSerializer;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JwsSerializer;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * The acceptance of issue #165 (OIDC Core §3.1.3.7 and §5.3.2): what the provider writes for a client
 * that asked to be written to in private. The client of the test kernel, "encrypted-app", publishes the
 * EC key of RFC 7515 appendix A.3 and registers an encryption for its ID tokens and a signature and an
 * encryption for its UserInfo answer; this test holds the private half and opens what it receives, the
 * way that client would.
 *
 * A client that registered nothing receives what it always received, which the last test of the file says
 * on the very same endpoints.
 */
final class EncryptedForTheClientTest extends BrowserTestCase
{
    /**
     * RFC 7515 appendix A.3.1: the private half of the key the client publishes.
     */
    private const array PRIVATE_KEY = [
        'kty' => 'EC',
        'crv' => 'P-256',
        'kid' => 'encrypted-app-key',
        'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
        'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
        'd' => 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
    ];

    protected function setUp(): void
    {
        parent::setUp();
        self::signingKey();
    }

    /**
     * The ID token is a JWE and not a JWS: five parts, and nothing of its claims readable before it is
     * opened with the key of the client.
     */
    #[Test]
    public function theIdTokenOfAClientThatRegisteredAnEncryptionIsAJwe(): void
    {
        // When
        $idToken = $this->tokensOfTheEncryptedClient()['id_token'];

        // Then
        static::assertIsString($idToken);
        static::assertCount(5, explode('.', $idToken));
        static::assertStringNotContainsString('encrypted-app', (string) $idToken);
    }

    /**
     * The client opens it with its private key, and what it finds inside is the ID token the tenant
     * signed, which verifies against the published JWK Set as any other does.
     */
    #[Test]
    public function theClientOpensTheIdTokenAndVerifiesTheSignatureInside(): void
    {
        // Given
        $idToken = $this->tokensOfTheEncryptedClient()['id_token'];
        static::assertIsString($idToken);

        // When
        ['header' => $header, 'payload' => $signed] = $this->open($idToken);

        // Then
        static::assertSame('encrypted-app-key', $header['kid']);
        static::assertSame('JWT', $header['cty']);
        $claims = $this->verified($signed);
        static::assertSame('encrypted-app', $claims['aud']);
        static::assertSame('alice', $claims['preferred_username'] ?? 'alice');
    }

    /**
     * OIDC Core §5.3.2: the answer is served as "application/jwt", and the JWE carries the signed answer,
     * with the "iss" and the "aud" a JWT answer names.
     */
    #[Test]
    public function theUserInfoAnswerOfThatClientIsAJwt(): void
    {
        // Given
        $accessToken = $this->tokensOfTheEncryptedClient()['access_token'];
        static::assertIsString($accessToken);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('application/jwt', $response->headers->get('Content-Type'));
        ['payload' => $signed] = $this->open(self::string($response->getContent()));
        $claims = $this->verified($signed);
        static::assertSame('encrypted-app', $claims['aud']);
        static::assertSame(self::tenant()->issuer->value, $claims['iss']);
        static::assertArrayHasKey('sub', $claims);
    }

    /**
     * Nothing of this touches a client that did not ask: the demo client keeps receiving a signed ID
     * token and a JSON UserInfo answer, on the same endpoints and in the same run.
     */
    #[Test]
    public function aClientThatRegisteredNothingIsServedAsBefore(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $code = self::redirectedQuery($this->browser->getResponse())['code'];
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://demo.test/login/check',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );
        $tokens = self::json($this->browser->getResponse());

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::string($tokens['access_token']),
        ]);

        // Then
        static::assertCount(3, explode('.', self::string($tokens['id_token'])));
        static::assertSame('application/json', $this->browser->getResponse()->headers->get('Content-Type'));
    }

    /**
     * The code flow of the client that is written to in private, signed in as alice.
     *
     * @return array<string, mixed>
     */
    private function tokensOfTheEncryptedClient(): array
    {
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('encrypted-app', [
            'redirect_uri' => 'https://encrypted.test/callback',
        ]));
        $code = self::redirectedQuery($this->browser->getResponse())['code'];
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://encrypted.test/callback',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('encrypted-app:encrypted-secret-of-at-least-32-characters'),
            ],
        );

        return self::json($this->browser->getResponse());
    }

    /**
     * What the client does with what it receives: open the JWE with its own key.
     *
     * @return array{header: array<string, mixed>, payload: string}
     */
    private function open(string $compactJwe): array
    {
        $jwe = new JweSerializer()->unserialize($compactJwe);
        static::assertTrue(new JWEDecrypter(Algorithms::encryption()->manager())->decryptUsingKey($jwe, new JWK(self::PRIVATE_KEY), 0));
        $payload = $jwe->getPayload();
        static::assertIsString($payload);

        return [
            'header' => $jwe->getSharedProtectedHeader(),
            'payload' => $payload,
        ];
    }

    /**
     * And then: verify the signature inside against the JWK Set the provider publishes.
     *
     * @return array<string, mixed>
     */
    private function verified(string $compactJws): array
    {
        $this->browser->request('GET', '/jwks');
        $published = self::json($this->browser->getResponse());
        static::assertIsArray($published['keys']);
        /** @var array<int, array<string, mixed>> $keys */
        $keys = $published['keys'];
        $jws = new JwsSerializer()->unserialize($compactJws);
        static::assertTrue(new JWSVerifier(Algorithms::all()->manager())->verifyWithKeySet(
            $jws,
            new JWKSet(array_map(static fn (array $key): JWK => new JWK($key), $keys)),
            0,
        ));
        $payload = $jws->getPayload();
        static::assertIsString($payload);
        /** @var array<string, mixed> $claims */
        $claims = json_decode($payload, true, 8, JSON_THROW_ON_ERROR);
        static::assertGreaterThan(0, count($claims));

        return $claims;
    }
}
