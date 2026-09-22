<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Oidc\Tests\Fixture\Proofs;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 9449 end to end, through HTTP: an authorization request that reserves its code for a key, the code
 * exchanged by the holder of that key, the tokens bound to it, and the provider's own resource refusing
 * them to anybody else. A public client, because a client with no credentials is the one binding proves
 * the most for.
 */
final class DpopFlowTest extends BrowserTestCase
{
    private const string CLIENT = 'dpop-app';

    private const string REDIRECT_URI = 'https://dpop.test/callback';

    /**
     * The origin of the issuer of the test kernel, which is what the provider publishes its endpoints
     * under and what a proof names in its "htu" (RFC 9449 §4.3).
     */
    private const string ISSUER = 'https://op.test';

    /**
     * A proof is used once (RFC 9449 §11.1), so each one made here carries an identifier of its own.
     */
    private static int $proofs = 0;

    /**
     * RFC 9449 §5: the response says the tokens are presented under the DPoP scheme, and §6.1: the
     * "at+jwt" carries the thumbprint of the key in its "cnf".
     */
    #[Test]
    public function theTokensOfARequestThatProvedAKeyAreBoundToIt(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));

        // When
        $tokens = $this->exchangeTheCode();

        // Then
        static::assertSame('DPoP', $tokens['token_type']);
        static::assertSame(
            [
                'jkt' => Proofs::thumbprintOf(Proofs::key())->thumbprint,
            ],
            self::claimsOf(self::string($tokens['access_token']))['cnf'],
        );
    }

    /**
     * RFC 9449 §7.1: the resource serves the token to the holder of the key, who proves it again for
     * that very request and for that very token.
     */
    #[Test]
    public function aBoundTokenIsServedToWhoeverProvesTheKeyAgain(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $accessToken = self::string($this->exchangeTheCode()['access_token']);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'DPoP ' . $accessToken,
            'HTTP_DPOP' => $this->proof('GET', self::ISSUER . '/userinfo', $accessToken),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('alice-subject', self::json($response)['sub']);
    }

    /**
     * A token issued against one key and presented with a proof of another opens nothing.
     */
    #[Test]
    public function aBoundTokenIsRefusedToAProofOfAnotherKey(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $accessToken = self::string($this->exchangeTheCode()['access_token']);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'DPoP ' . $accessToken,
            'HTTP_DPOP' => $this->proof('GET', self::ISSUER . '/userinfo', $accessToken, Proofs::otherKey()),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_token', self::json($response)['error']);
    }

    /**
     * RFC 9449 §7.1: presented as a bearer token, the same token is refused, and the challenge names
     * the scheme that would have worked.
     */
    #[Test]
    public function aBoundTokenPresentedAsABearerTokenIsRefusedWithTheDpopChallenge(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $accessToken = self::string($this->exchangeTheCode()['access_token']);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertStringStartsWith('DPoP error="invalid_token"', self::string($response->headers->get('WWW-Authenticate')));
    }

    /**
     * RFC 9449 §10.1: the code was reserved for the key the authorization request named, and a token
     * request proving another key does not collect it.
     */
    #[Test]
    public function aCodeReservedForAKeyIsNotExchangedByAnother(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $code = $this->codeReservedForTheKey();

        // When
        $this->browser->request('POST', '/token', self::tokenParameters($code), server: [
            'HTTP_DPOP' => $this->proof('POST', self::ISSUER . '/token', null, Proofs::otherKey()),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_grant', self::json($response)['error']);
    }

    /**
     * RFC 9449 §11.1: a proof taken off the wire and sent again is refused, however fresh it still is.
     */
    #[Test]
    public function aProofPresentedTwiceIsRefused(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $accessToken = self::string($this->exchangeTheCode()['access_token']);
        $proof = $this->proof('GET', self::ISSUER . '/userinfo', $accessToken);
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'DPoP ' . $accessToken,
            'HTTP_DPOP' => $proof,
        ]);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'DPoP ' . $accessToken,
            'HTTP_DPOP' => $proof,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_dpop_proof', self::json($response)['error']);
    }

    /**
     * A client that sends no proof at all keeps working: nothing of this is asked of a client that does
     * not bind its tokens.
     */
    #[Test]
    public function aClientThatSendsNoProofIsServedAsBefore(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters(self::CLIENT, [
            'redirect_uri' => self::REDIRECT_URI,
        ]));
        $code = self::string(self::redirectedQuery($this->browser->getResponse())['code'] ?? null);

        // When
        $this->browser->request('POST', '/token', self::tokenParameters($code));

        // Then
        $tokens = self::json($this->browser->getResponse());
        static::assertSame('Bearer', $tokens['token_type']);
        static::assertArrayNotHasKey('cnf', self::claimsOf(self::string($tokens['access_token'])));
    }

    /**
     * The code flow of a client that binds its tokens: the authorization request names the key
     * ("dpop_jkt", RFC 9449 §10), and the code is exchanged with a proof of it.
     *
     * @return array<string, mixed>
     */
    private function exchangeTheCode(): array
    {
        $code = $this->codeReservedForTheKey();
        $this->browser->request('POST', '/token', self::tokenParameters($code), server: [
            'HTTP_DPOP' => $this->proof('POST', self::ISSUER . '/token'),
        ]);
        $tokens = self::json($this->browser->getResponse());
        static::assertIsString($tokens['access_token'] ?? null, self::string($this->browser->getResponse()->getContent()));

        return $tokens;
    }

    private function codeReservedForTheKey(): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters(self::CLIENT, [
            'redirect_uri' => self::REDIRECT_URI,
            'dpop_jkt' => Proofs::thumbprintOf(Proofs::key())->thumbprint,
        ]));

        return self::string(self::redirectedQuery($this->browser->getResponse())['code'] ?? null);
    }

    private function proof(string $method, string $url, ?string $accessToken = null, ?JWK $key = null): string
    {
        return Proofs::proof(
            $method,
            $url,
            Clock::get()->now(),
            $accessToken,
            [
                'jti' => 'proof-' . self::$proofs++,
            ],
            [],
            $key,
        );
    }

    /**
     * @return array<string, string>
     */
    private static function tokenParameters(string $code): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::REDIRECT_URI,
            'code_verifier' => self::CODE_VERIFIER,
            'client_id' => self::CLIENT,
        ];
    }
}
