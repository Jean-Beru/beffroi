<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 7009 §2, Architecture §4.12
 */
final class RevocationControllerTest extends BrowserTestCase
{
    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function theRevocationEndpointIsPostOnly(): void
    {
        // When
        $this->browser->request('GET', '/revoke', [
            'token' => 'whatever',
        ]);

        // Then
        static::assertSame(Response::HTTP_METHOD_NOT_ALLOWED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 7009 §2.2
     */
    #[Test]
    public function anUnknownTokenIsAnsweredWithNothing(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/revoke',
            [
                'token' => 'unknown',
            ],
            server: self::demoCredentials(),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('', $response->getContent());
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * RFC 7009 §2.2.1, RFC 6749 §5.2
     */
    #[Test]
    public function aWrongSecretIsChallenged(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/revoke',
            [
                'token' => 'whatever',
            ],
            server: self::demoCredentials('wrong-secret-of-at-least-32-characters'),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * RFC 7009 §2.2.1
     */
    #[Test]
    public function aJwtAccessTokenIsRefusedAsUnsupported(): void
    {
        // Given
        $accessToken = $this->jwtAccessTokenOfTheDemoClient();

        // When
        $this->browser->request(
            'POST',
            '/revoke',
            [
                'token' => $accessToken,
            ],
            server: self::demoCredentials(),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('unsupported_token_type', self::json($response)['error']);
    }

    /**
     * RFC 7009 §2.2
     */
    #[Test]
    public function aJwtAccessTokenOfASessionThatEndedIsAnsweredWithNothing(): void
    {
        // Given
        self::signingKey();
        $session = $this->signIn(self::user('alice'));
        $accessToken = $this->jwtAccessTokenOfTheSignedInBrowser();
        $this->endSession($session);

        // When
        $this->browser->request(
            'POST',
            '/revoke',
            [
                'token' => $accessToken,
            ],
            server: self::demoCredentials(),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('', $response->getContent());
    }

    /**
     * RFC 7009 §2.1
     */
    #[Test]
    public function aRevokedRefreshTokenIsRefusedByTheTokenEndpoint(): void
    {
        // Given
        $this->jwtAccessTokenOfTheDemoClient();
        $refreshToken = self::string(self::json($this->browser->getResponse())['refresh_token']);
        $this->browser->request(
            'POST',
            '/revoke',
            [
                'token' => $refreshToken,
                'token_type_hint' => 'refresh_token',
            ],
            server: self::demoCredentials(),
        );
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
            ],
            server: self::demoCredentials(),
        );

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('invalid_grant', self::json($this->browser->getResponse())['error']);
    }

    private function jwtAccessTokenOfTheDemoClient(): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));

        return $this->jwtAccessTokenOfTheSignedInBrowser();
    }

    private function jwtAccessTokenOfTheSignedInBrowser(): string
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
            server: self::demoCredentials(),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['access_token']);
    }

    /**
     * @return array<string, string>
     */
    private static function demoCredentials(string $secret = 'demo-secret-of-at-least-32-characters-long'): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:' . $secret),
        ];
    }
}
