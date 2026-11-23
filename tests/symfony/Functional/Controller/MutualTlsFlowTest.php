<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\Tls\EdgeClientCertificateResolver;
use Beffroi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Beffroi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8705 §2.1, §3, §3.2
 */
final class MutualTlsFlowTest extends BrowserTestCase
{
    /**
     * RFC 8705 §2.1.2
     */
    #[Test]
    public function aClientAuthenticatesWithTheCertificateItRegistered(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));

        // When
        $this->exchangeTheCode('mtls-app', 'https://mtls.test/callback', Certificates::client());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertIsString(self::json($response)['access_token']);
    }

    #[Test]
    public function anotherCertificateOfTheSameAuthorityIsRefused(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));

        // When
        $this->exchangeTheCode('mtls-app', 'https://mtls.test/callback', Certificates::other());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * RFC 8705 §2.1, §7.4
     */
    #[Test]
    #[DataProvider('provideCertificatesNoTrustedAuthorityIssued')]
    public function aCertificateCarryingTheRegisteredNameThatNoTrustedAuthorityIssuedIsRefused(ClientCertificate $certificate): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));

        // When
        $this->exchangeTheCode('mtls-app', 'https://mtls.test/callback', $certificate);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * @return iterable<string, array{ClientCertificate}>
     */
    public static function provideCertificatesNoTrustedAuthorityIssued(): iterable
    {
        yield 'self-signed' => [Certificates::selfSigned()];

        yield 'issued by another authority' => [Certificates::ofAnotherAuthority()];
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function aCertificateCarriedInAHeaderIsRefused(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $code = $this->codeOf('mtls-app', 'https://mtls.test/callback');

        // When
        $this->browser->request('POST', '/token', self::tokenParameters($code, 'mtls-app', 'https://mtls.test/callback'), server: [
            'HTTP_X_FORWARDED_CLIENT_CERT' => Certificates::pemOf(Certificates::client()),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_request', self::json($response)['error']);
    }

    /**
     * RFC 8705 §3.1
     */
    #[Test]
    public function theSelfContainedTokenCarriesTheThumbprintOfTheCertificate(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));

        // When
        $accessToken = $this->accessTokenOf('mtls-app', 'https://mtls.test/callback', Certificates::client());

        // Then
        static::assertSame(
            [
                'x5t#S256' => Certificates::client()->x5tS256(),
            ],
            self::claimsOf($accessToken)['cnf'],
        );
    }

    /**
     * RFC 8705 §3
     */
    #[Test]
    #[DataProvider('provideBoundClients')]
    public function aBoundTokenIsServedWhenItsCertificateIsPresentedAgain(string $clientId, string $redirectUri): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $accessToken = $this->accessTokenOf($clientId, $redirectUri, Certificates::client());

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
            EdgeClientCertificateResolver::VARIABLE => Certificates::pemOf(Certificates::client()),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('alice-subject', self::json($response)['sub']);
    }

    /**
     * RFC 8705 §3.2
     */
    #[Test]
    #[DataProvider('provideBoundClients')]
    public function aBoundTokenIsRefusedWithoutItsCertificate(string $clientId, string $redirectUri): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $accessToken = $this->accessTokenOf($clientId, $redirectUri, Certificates::client());

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_token', self::json($response)['error']);
    }

    /**
     * Architecture §4.6
     *
     * @return iterable<string, array{string, string}>
     */
    public static function provideBoundClients(): iterable
    {
        yield 'an at+jwt carrying its own "cnf"' => ['mtls-app', 'https://mtls.test/callback'];

        yield 'an opaque token whose record carries it' => ['mtls-opaque-app', 'https://mtls.test/opaque'];
    }

    private function accessTokenOf(string $clientId, string $redirectUri, ClientCertificate $certificate): string
    {
        $this->exchangeTheCode($clientId, $redirectUri, $certificate);

        return self::string(self::json($this->browser->getResponse())['access_token'] ?? null);
    }

    private function exchangeTheCode(string $clientId, string $redirectUri, ClientCertificate $certificate): void
    {
        $code = $this->codeOf($clientId, $redirectUri);
        $this->browser->request('POST', '/token', self::tokenParameters($code, $clientId, $redirectUri), server: [
            EdgeClientCertificateResolver::VARIABLE => Certificates::pemOf($certificate),
        ]);
    }

    private function codeOf(string $clientId, string $redirectUri): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => $redirectUri,
        ]));

        return self::string(self::redirectedQuery($this->browser->getResponse())['code'] ?? null);
    }

    /**
     * RFC 8705 §2
     *
     * @return array<string, string>
     */
    private static function tokenParameters(string $code, string $clientId, string $redirectUri): array
    {
        return [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => self::CODE_VERIFIER,
            'client_id' => $clientId,
        ];
    }
}
