<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 6749 §3.2, §5.1, §5.2, Architecture §4.5
 */
final class TokenControllerTest extends BrowserTestCase
{
    /**
     * RFC 6749 §3.2
     */
    #[Test]
    public function theTokenEndpointIsPostOnly(): void
    {
        // When
        $this->browser->request('GET', '/token', [
            'grant_type' => 'authorization_code',
        ]);

        // Then
        static::assertSame(Response::HTTP_METHOD_NOT_ALLOWED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 6749 §5.2
     */
    #[Test]
    public function aWrongSecretInTheHeaderIsChallenged(): void
    {
        // When
        $this->postWithAWrongSecret();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertStringStartsWith('Basic', self::string($response->headers->get('WWW-Authenticate')));
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * RFC 6749 §5.1, §5.2
     */
    #[Test]
    public function anErrorOfTheTokenEndpointIsNotCached(): void
    {
        // When
        $this->postWithAWrongSecret();

        // Then
        $response = $this->browser->getResponse();
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('no-cache', $response->headers->get('Pragma'));
    }

    /**
     * RFC 6749 §5.2
     */
    #[Test]
    public function anUnknownGrantTypeIsRefused(): void
    {
        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'password',
            'client_id' => 'native-app',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('unsupported_grant_type', self::json($response)['error']);
    }

    /**
     * RFC 7523 §2.2, RFC 6749 §5.2
     */
    #[Test]
    public function anAssertionOfAnotherTypeIsAnInvalidRequest(): void
    {
        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'client_credentials',
            'client_assertion' => 'an.assertion.here',
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:saml2-bearer',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_request', self::json($response)['error']);
    }

    /**
     * RFC 6749 §3.2
     */
    #[Test]
    public function theQueryStringIsNotRead(): void
    {
        // When
        $this->browser->request('POST', '/token?grant_type=authorization_code&client_id=native-app');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * RFC 6749 §6, Architecture §4.5, FAPI 2.0 Security Profile §5.3.2.1-9
     */
    #[Test]
    public function theRefreshTokenOfAConfidentialClientStands(): void
    {
        // Given
        $refreshToken = $this->refreshTokenOfTheDemoClient();

        // When
        $this->refresh($refreshToken);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $renewed = self::json($response);
        static::assertIsString($renewed['access_token']);
        static::assertIsString($renewed['id_token']);
        static::assertArrayNotHasKey('refresh_token', $renewed);
        static::assertSame('openid profile', $renewed['scope']);
    }

    /**
     * RFC 9700 §4.14.2
     */
    #[Test]
    public function theRefreshTokenOfAConfidentialClientRefreshesAgain(): void
    {
        // Given
        $refreshToken = $this->refreshTokenOfTheDemoClient();
        $this->refresh($refreshToken);

        // When
        $this->refresh($refreshToken);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertIsString(self::json($response)['access_token']);
    }

    /**
     * OIDC Core §10.1.1, Architecture §3.3
     */
    #[Test]
    public function aRefreshAfterARotationIssuesTokensSignedByTheNewKey(): void
    {
        // Given
        $previous = self::signingKey();
        $refreshToken = $this->refreshTokenOfTheDemoClient();
        $active = self::signingKey();

        // When
        $this->refresh($refreshToken);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $renewed = self::json($response);
        static::assertNotSame($previous->kid, $active->kid);
        static::assertSame($active->kid, self::kidOf(self::string($renewed['access_token'])));
        static::assertSame($active->kid, self::kidOf(self::string($renewed['id_token'])));
    }

    private function postWithAWrongSecret(): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => 'whatever',
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:wrong-secret-of-at-least-32-characters'),
            ],
        );
    }

    private function refreshTokenOfTheDemoClient(): string
    {
        self::signingKey();
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
            server: self::demoCredentials(),
        );

        return self::string(self::json($this->browser->getResponse())['refresh_token']);
    }

    private function refresh(string $refreshToken): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
            ],
            server: self::demoCredentials(),
        );
    }

    /**
     * @return array<string, string>
     */
    private static function demoCredentials(): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
        ];
    }
}
