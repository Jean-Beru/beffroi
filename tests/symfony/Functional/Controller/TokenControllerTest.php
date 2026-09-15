<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 6749 §3.2, §5.1, §5.2 and architecture §4.5: the token endpoint answers JSON, never cached,
 * the client authenticated before anything is read.
 */
final class TokenControllerTest extends BrowserTestCase
{
    /**
     * RFC 6749 §3.2: POST only.
     */
    #[Test]
    public function theTokenEndpointIsPostOnly(): void
    {
        $this->browser->request('GET', '/token', [
            'grant_type' => 'authorization_code',
        ]);

        static::assertSame(Response::HTTP_METHOD_NOT_ALLOWED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 6749 §5.2: invalid_client is 401 with the challenge when the header was used.
     */
    #[Test]
    public function aWrongSecretInTheHeaderIsChallenged(): void
    {
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => 'whatever',
        ], server: [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:wrong-secret-of-at-least-32-characters'),
        ]);

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('no-cache', $response->headers->get('Pragma'));
        static::assertStringStartsWith('Basic', self::string($response->headers->get('WWW-Authenticate')));
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * RFC 6749 §5.2: a grant the provider does not offer.
     */
    #[Test]
    public function anUnknownGrantTypeIsRefused(): void
    {
        $this->browser->request('POST', '/token', [
            'grant_type' => 'password',
            'client_id' => 'native-app',
        ]);

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('unsupported_grant_type', self::json($response)['error']);
    }

    /**
     * RFC 6749 §3.2: the parameters are read from the form body, never from the query string.
     */
    #[Test]
    public function theQueryStringIsNotRead(): void
    {
        $this->browser->request('POST', '/token?grant_type=authorization_code&client_id=native-app');

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * RFC 6749 §6 and architecture §4.5: a confidential client gets a refresh token, rotated at each use,
     * through the same endpoint.
     */
    #[Test]
    public function aRefreshTokenIsRotated(): void
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $code = self::redirectedQuery($this->browser->getResponse())['code'];
        $credentials = [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
        ];
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://demo.test/login/check',
            'code_verifier' => self::CODE_VERIFIER,
        ], server: $credentials);
        $tokens = self::json($this->browser->getResponse());
        $refreshToken = self::string($tokens['refresh_token']);

        $this->browser->request('POST', '/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ], server: $credentials);

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $renewed = self::json($response);
        static::assertIsString($renewed['access_token']);
        static::assertIsString($renewed['id_token']);
        static::assertNotSame($refreshToken, $renewed['refresh_token']);
        static::assertSame('openid profile', $renewed['scope']);

        // RFC 9700 §4.13.2: the rotated token is refused
        $this->browser->request('POST', '/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ], server: $credentials);
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('invalid_grant', self::json($this->browser->getResponse())['error']);
    }
}
