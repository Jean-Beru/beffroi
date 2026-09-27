<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Bundle\Http\Tls\EdgeClientCertificateResolver;
use Heidi\Oidc\Domain\Client\Certificate\ClientCertificate;
use Heidi\Oidc\Tests\Fixture\Certificates;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8705 end to end, through HTTP: a client authenticated by the certificate its connection proved
 * (§2.1), the tokens of that request bound to it (§3), and the provider's own resource refusing them to
 * anybody else (§3.2). The certificate reaches the application the way the edge hands it over
 * (architecture §6, issue #157): a server variable, filled by the listener that carried out the
 * handshake.
 */
final class MutualTlsFlowTest extends BrowserTestCase
{
    /**
     * RFC 8705 §2.1.2: the client registered the subject distinguished name of its certificate, and the
     * certificate presented carries it.
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

    /**
     * The edge proved the chain; the provider judges the name. A certificate of the very same authority
     * that names somebody else authenticates nobody.
     */
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
     * Decision 0006: a certificate a client wrote in a header is not a certificate, and the request says
     * so instead of being served as one made without.
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
     * RFC 8705 §3.1: the access token of that request carries the thumbprint of the certificate in its
     * "cnf", which is what a resource server verifying it offline reads.
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
     * RFC 8705 §3: a bound token is honoured by the client that presents its certificate again, and by
     * nobody else, whichever shape the token has.
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
     * RFC 8705 §3.2: presented without that certificate, the same token is invalid_token. Whoever steals
     * a bound token holds bytes that open nothing.
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
     * The two shapes of access token of architecture §4.6, each one registered by a client the provider
     * recognises by its certificate.
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

    /**
     * The code flow of a client the provider recognises by its certificate: the authorization request on
     * the session the browser holds, then the code exchanged on a connection that presented one.
     */
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
     * RFC 8705 §2: the client names itself in the body and proves it with the certificate of the
     * connection, which is the whole of what it sends.
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
