<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * OIDC Core §5.3, RFC 6750 §2 and §3, architecture §4.7: where the token is read from, and how a
 * refusal is answered.
 */
final class UserInfoControllerTest extends BrowserTestCase
{
    /**
     * RFC 6750 §3.1: no token at all is the bare challenge, no error code, no body.
     */
    #[Test]
    public function aRequestWithoutATokenGetsTheBareChallenge(): void
    {
        // When
        $this->browser->request('GET', '/userinfo');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('Bearer', $response->headers->get('WWW-Authenticate'));
        static::assertSame('', $response->getContent());
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * RFC 6750 §2.3, RFC 9700 §4.3.2: a token in the query string is not a token.
     */
    #[Test]
    public function aTokenInTheQueryStringIsNotRead(): void
    {
        // When
        $this->browser->request('GET', '/userinfo', [
            'access_token' => 'whatever',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('Bearer', $response->headers->get('WWW-Authenticate'));
    }

    /**
     * RFC 6750 §3.1: a token that is not one of the provider's is invalid_token, with the error in the
     * challenge and repeated in the body.
     */
    #[Test]
    public function aForeignTokenIsInvalid(): void
    {
        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer not.a.token',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertStringStartsWith('Bearer error="invalid_token"', self::string($response->headers->get('WWW-Authenticate')));
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertSame('invalid_token', self::json($response)['error']);
    }

    /**
     * RFC 6750 §2.2: the token may come in the form body of a POST.
     */
    #[Test]
    public function aTokenInTheFormBodyOfAPostIsRead(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('oidc-demo'));
        $code = self::redirectedQuery($this->browser->getResponse())['code'];
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://demo.test/login/check',
            'code_verifier' => self::CODE_VERIFIER,
        ], server: [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
        ]);
        $accessToken = self::string(self::json($this->browser->getResponse())['access_token']);

        // When
        $this->browser->request('POST', '/userinfo', [
            'access_token' => $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('alice-subject', self::json($response)['sub']);
    }
}
