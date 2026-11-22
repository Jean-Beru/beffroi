<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_decode;
use function base64_encode;
use function explode;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use function strtr;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 7662 §2, RFC 9701 §4, §5, Architecture §4.12
 */
final class IntrospectionControllerTest extends BrowserTestCase
{
    /**
     * RFC 7662 §2.1
     */
    #[Test]
    public function theIntrospectionEndpointIsPostOnly(): void
    {
        // When
        $this->browser->request('GET', '/introspect', [
            'token' => 'whatever',
        ]);

        // Then
        static::assertSame(Response::HTTP_METHOD_NOT_ALLOWED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 7662 §2.3, RFC 6749 §5.2
     */
    #[Test]
    public function aWrongSecretIsChallenged(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => 'whatever',
            ],
            server: self::credentials('opaque-app', 'wrong-secret-of-at-least-32-characters'),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertStringStartsWith('Basic', self::string($response->headers->get('WWW-Authenticate')));
        static::assertSame('invalid_client', self::json($response)['error']);
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function aClientRegisteredForOpaqueTokensGetsOneThatOpensUserInfo(): void
    {
        // Given
        $accessToken = $this->opaqueAccessToken();

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $accessToken);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('alice-subject', self::json($response)['sub']);
    }

    /**
     * RFC 7662 §2.2
     */
    #[Test]
    public function anActiveTokenIsDescribedToItsClient(): void
    {
        // Given
        $accessToken = $this->opaqueAccessToken();

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
                'token_type_hint' => 'access_token',
            ],
            server: self::credentials('opaque-app'),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        $members = self::json($response);
        static::assertTrue($members['active']);
        static::assertSame('opaque-app', $members['client_id']);
        static::assertSame('alice-subject', $members['sub']);
        static::assertSame('openid profile', $members['scope']);
        static::assertSame('https://op.test', $members['iss']);
        static::assertSame('Bearer', $members['token_type']);
    }

    /**
     * RFC 7662 §2.2
     */
    #[Test]
    public function toAnotherClientTheTokenIsInactive(): void
    {
        // Given
        $accessToken = $this->opaqueAccessToken();

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
            ],
            server: self::credentials('oidc-demo', 'demo-secret-of-at-least-32-characters-long'),
        );

        // Then
        static::assertSame(
            [
                'active' => false,
            ],
            self::json($this->browser->getResponse()),
        );
    }

    /**
     * RFC 9701 §4, §5
     */
    #[Test]
    public function theResponseIsSignedWhenTheAcceptHeaderAsksForIt(): void
    {
        // Given
        $accessToken = $this->opaqueAccessToken();

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
            ],
            server: self::credentials('opaque-app')
            + [
                'HTTP_ACCEPT' => 'application/token-introspection+jwt, application/json',
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('application/token-introspection+jwt', $response->headers->get('Content-Type'));
        [$header, $payload] = explode('.', self::string($response->getContent()));
        static::assertSame('token-introspection+jwt', self::decodeSegment($header)['typ']);
        $claims = self::decodeSegment($payload);
        static::assertSame('https://op.test', $claims['iss']);
        static::assertSame('opaque-app', $claims['aud']);
        static::assertIsArray($claims['token_introspection']);
        static::assertTrue($claims['token_introspection']['active']);
        static::assertSame('alice-subject', $claims['token_introspection']['sub']);
    }

    /**
     * RFC 9701 §6, §7
     */
    #[Test]
    public function theDocumentAnnouncesTheAlgorithmASignedResponseCarries(): void
    {
        // Given
        $accessToken = $this->opaqueAccessToken();
        $this->browser->request('GET', '/.well-known/openid-configuration');
        $announced = self::json($this->browser->getResponse())['introspection_signing_alg_values_supported'];

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
            ],
            server: self::credentials('opaque-app')
            + [
                'HTTP_ACCEPT' => 'application/token-introspection+jwt',
            ],
        );

        // Then
        [$header] = explode('.', self::string($this->browser->getResponse()->getContent()));
        static::assertSame([self::decodeSegment($header)['alg']], $announced);
    }

    /**
     * RFC 7009, RFC 7662
     */
    #[Test]
    public function aRevokedTokenIsInactiveAndOpensNothing(): void
    {
        // Given
        $accessToken = $this->opaqueAccessToken();
        $this->browser->request(
            'POST',
            '/revoke',
            [
                'token' => $accessToken,
            ],
            server: self::credentials('opaque-app'),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
            ],
            server: self::credentials('opaque-app'),
        );
        $introspection = self::json($this->browser->getResponse());
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        static::assertSame(
            [
                'active' => false,
            ],
            $introspection,
        );
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Architecture §4.9
     */
    #[Test]
    public function aTokenOfASessionThatEndedIsInactive(): void
    {
        // Given
        self::signingKey();
        $session = $this->signIn(self::user('alice'));
        $accessToken = $this->jwtAccessToken();
        $this->endSession($session);

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
            ],
            server: self::credentials('oidc-demo', 'demo-secret-of-at-least-32-characters-long'),
        );

        // Then
        static::assertSame(
            [
                'active' => false,
            ],
            self::json($this->browser->getResponse()),
        );
    }

    private function jwtAccessToken(): string
    {
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
            server: self::credentials('oidc-demo', 'demo-secret-of-at-least-32-characters-long'),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['access_token']);
    }

    private function opaqueAccessToken(): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('opaque-app', [
            'redirect_uri' => 'https://opaque.test/callback',
        ]));
        $code = self::redirectedQuery($this->browser->getResponse())['code'];
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => 'https://opaque.test/callback',
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: self::credentials('opaque-app'),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['access_token']);
    }

    /**
     * @return array<string, string>
     */
    private static function credentials(string $clientId, string $secret = 'opaque-secret-of-at-least-32-characters-long'): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeSegment(string $segment): array
    {
        $decoded = json_decode((string) base64_decode(strtr($segment, '-_', '+/'), true), true, 8, JSON_THROW_ON_ERROR);
        static::assertIsArray($decoded);
        $members = [];
        foreach ($decoded as $name => $value) {
            $members[(string) $name] = $value;
        }

        return $members;
    }
}
