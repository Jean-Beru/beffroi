<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use App\Http\FapiInteractionId;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §5.3, §10.1.1, RFC 6750 §2, §3, Architecture §3.3, §4.7, FAPI 1.0 Advanced Final §6.2.1
 */
final class UserInfoControllerTest extends BrowserTestCase
{
    /**
     * FAPI 1.0 Advanced Final §6.2.1, RFC 4122
     */
    private const string INTERACTION_ID = '4b2a1c6e-7d3f-4a91-8f52-9c0d6e1b7a84';

    /**
     * RFC 6750 §3.1
     */
    #[Test]
    public function aRequestWithoutATokenGetsTheBareChallenge(): void
    {
        // When
        $this->browser->request('GET', '/userinfo');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('Bearer, DPoP algs="RS256 PS256 ES256 EdDSA"', $response->headers->get('WWW-Authenticate'));
        static::assertSame('', $response->getContent());
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * RFC 6750 §2.3, RFC 9700 §4.3.2
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
        static::assertSame('Bearer, DPoP algs="RS256 PS256 ES256 EdDSA"', $response->headers->get('WWW-Authenticate'));
    }

    /**
     * RFC 6750 §3.1
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
     * RFC 6750 §2.2
     */
    #[Test]
    public function aTokenInTheFormBodyOfAPostIsRead(): void
    {
        // Given
        self::signingKey();
        $accessToken = $this->accessTokenOfTheDemoClient();

        // When
        $this->browser->request('POST', '/userinfo', [
            'access_token' => $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('alice-subject', self::json($response)['sub']);
    }

    /**
     * OIDC Core §10.1.1
     */
    #[Test]
    public function anAccessTokenSignedBeforeARotationIsAcceptedAfterIt(): void
    {
        // Given
        $previous = self::signingKey();
        $accessToken = $this->accessTokenOfTheDemoClient();
        self::signingKey();

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame($previous->kid, self::kidOf($accessToken));
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('alice-subject', self::json($response)['sub']);
    }

    /**
     * Architecture §3.3, RFC 6750 §3.1
     */
    #[Test]
    public function anAccessTokenSignedByARetiredKeyIsInvalid(): void
    {
        // Given
        $previous = self::signingKey();
        $accessToken = $this->accessTokenOfTheDemoClient();
        self::signingKey();
        self::retireKey($previous);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertStringStartsWith('Bearer error="invalid_token"', self::string($response->headers->get('WWW-Authenticate')));
        static::assertSame('invalid_token', self::json($response)['error']);
    }

    /**
     * Architecture §4.9
     */
    #[Test]
    public function anAtJwtOfASessionThatEndedIsRefused(): void
    {
        // Given
        self::signingKey();
        $session = $this->signIn(self::user('alice'));
        $accessToken = $this->codeFlowOfTheDemoClient();
        $this->endSession($session);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertStringContainsString('invalid_token', self::string($response->headers->get('WWW-Authenticate')));
    }

    /**
     * FAPI 1.0 Advanced Final §6.2.1
     */
    #[Test]
    public function theAnswerCarriesTheInteractionIdTheRequestNamed(): void
    {
        // Given
        self::signingKey();
        $accessToken = $this->accessTokenOfTheDemoClient();

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
            'HTTP_X_FAPI_INTERACTION_ID' => self::INTERACTION_ID,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame(self::INTERACTION_ID, $response->headers->get(FapiInteractionId::HEADER));
    }

    /**
     * FAPI 1.0 Advanced Final §6.2.1
     */
    #[Test]
    public function theAnswerOfARequestThatNamedNoInteractionIdCarriesOneDrawnForIt(): void
    {
        // Given
        self::signingKey();
        $accessToken = $this->accessTokenOfTheDemoClient();

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertTrue(Uuid::isValid(self::string($response->headers->get(FapiInteractionId::HEADER))));
    }

    /**
     * FAPI 1.0 Advanced Final §6.2.1, RFC 6750 §3.1
     */
    #[Test]
    public function aRefusalCarriesTheInteractionIdTheRequestNamed(): void
    {
        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_X_FAPI_INTERACTION_ID' => self::INTERACTION_ID,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame(self::INTERACTION_ID, $response->headers->get(FapiInteractionId::HEADER));
    }

    private function accessTokenOfTheDemoClient(): string
    {
        $this->signIn(self::user('alice'));

        return $this->codeFlowOfTheDemoClient();
    }

    private function codeFlowOfTheDemoClient(): string
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
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('oidc-demo:demo-secret-of-at-least-32-characters-long'),
            ],
        );

        return self::string(self::json($this->browser->getResponse())['access_token']);
    }
}
