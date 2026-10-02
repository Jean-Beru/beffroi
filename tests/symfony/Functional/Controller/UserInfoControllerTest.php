<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Beffroi\Bundle\Http\FapiInteractionId;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §5.3, RFC 6750 §2 and §3, architecture §4.7: where the token is read from, and how a
 * refusal is answered; across a rotation (OIDC Core §10.1.1, architecture §3.3), which tokens still
 * open the door; and what every answer of this resource names its exchange with (FAPI 1.0 Advanced
 * Final §6.2.1).
 */
final class UserInfoControllerTest extends BrowserTestCase
{
    /**
     * What a client names an exchange with (FAPI 1.0 Advanced Final §6.2.1): an RFC 4122 UUID.
     */
    private const string INTERACTION_ID = '4b2a1c6e-7d3f-4a91-8f52-9c0d6e1b7a84';

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
        static::assertSame('Bearer, DPoP', $response->headers->get('WWW-Authenticate'));
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
        static::assertSame('Bearer, DPoP', $response->headers->get('WWW-Authenticate'));
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
     * OIDC Core §10.1.1: an "at+jwt" signed before a rotation is accepted after it, while the key that
     * signed it is retiring, until the token expires.
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
     * Architecture §3.3: once the key that signed a token is retired, the token is refused like one
     * signed by nobody the provider knows: invalid_token (RFC 6750 §3.1), whatever its "exp".
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
     * The "at+jwt" oidc-demo gets from the code flow of alice, signed by the key active at that moment.
     */
    /**
     * Architecture §4.9 and issue #150: what a logout ends, it ends for an "at+jwt" too. A resource
     * server that verifies it offline cannot know, which is the trade of that shape; UserInfo is the
     * provider's own resource and knows where its sessions live.
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
     * FAPI 1.0 Advanced Final §6.2.1: the answer of a resource of the provider carries the
     * "x-fapi-interaction-id" the request named, so that the client and the provider name one exchange.
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
     * FAPI 1.0 Advanced Final §6.2.1: a request that named none is answered with one drawn for it, an
     * exchange the provider can name being the point of the header.
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
     * FAPI 1.0 Advanced Final §6.2.1: the exchange is named whatever became of the request, so a refusal
     * carries the header as an answer does; here the bare challenge of RFC 6750 §3.1, which has no body
     * to say anything in.
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

    /**
     * The same code flow without the sign-in, for the tests that need the session it opened.
     */
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
