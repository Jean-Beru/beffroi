<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Oidc\Tests\Fixture\Proofs;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;
use function array_map;
use function implode;

/**
 * RFC 9449
 */
final class DpopFlowTest extends BrowserTestCase
{
    private const string CLIENT = 'dpop-app';

    private const string REDIRECT_URI = 'https://dpop.test/callback';

    /**
     * RFC 9449 §4.3
     */
    private const string ISSUER = 'https://op.test';

    /**
     * A proof is used once (RFC 9449 §11.1), so each one made here carries an identifier of its own.
     */
    private static int $proofs = 0;

    /**
     * RFC 9449 §5, §6.1
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
     * RFC 9449 §7.1
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
     * RFC 9449 §7.1
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
     * RFC 9449 §7.2, §7.1
     */
    #[Test]
    public function anExpiredBoundTokenPresentedUnderDpopIsRefusedUnderTheDpopChallenge(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $accessToken = self::string($this->exchangeTheCode()['access_token']);
        self::mockTime(Clock::get()->now()->modify('+11 minutes'));

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'DPoP ' . $accessToken,
            'HTTP_DPOP' => $this->proof('GET', self::ISSUER . '/userinfo', $accessToken),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame(
            'DPoP error="invalid_token", error_description="The access token expired.", algs="RS256 PS256 ES256 EdDSA"',
            $response->headers->get('WWW-Authenticate'),
        );
    }

    /**
     * RFC 9449 §7.1, §5.1
     */
    #[Test]
    public function theChallengeNamesTheAlgorithmsTheDocumentAnnouncesForAProof(): void
    {
        // Given
        $this->browser->request('GET', '/.well-known/openid-configuration');
        $announced = self::json($this->browser->getResponse())['dpop_signing_alg_values_supported'];
        static::assertIsArray($announced);

        // When
        $this->browser->request('GET', '/userinfo');

        // Then
        static::assertSame(
            'Bearer, DPoP algs="' . implode(' ', array_map(self::string(...), $announced)) . '"',
            $this->browser->getResponse()->headers->get('WWW-Authenticate'),
        );
    }

    /**
     * RFC 9449 §10.1
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
     * RFC 9449 §11.1
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
     * RFC 9449 §10
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
