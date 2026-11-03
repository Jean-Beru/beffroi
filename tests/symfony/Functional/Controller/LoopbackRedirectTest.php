<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function http_build_query;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8252 §7.3 over HTTP, end to end: a native client registered for `http://127.0.0.1/callback` is
 * answered on the port the operating system handed it, and on nothing else. One step per test, on the test
 * kernel, the public "native-app" client of its configuration and the confidential "oidc-demo".
 */
final class LoopbackRedirectTest extends BrowserTestCase
{
    private const string REGISTERED = 'http://127.0.0.1/callback';

    private const string ON_ITS_PORT = 'http://127.0.0.1:53127/callback';

    /**
     * RFC 8252 §7.3: the port is what a native client cannot register in advance, so the code comes back to
     * the port the request named.
     */
    #[Test]
    public function aNativeClientIsAnsweredOnThePortItAsksFor(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->allow(self::ON_ITS_PORT);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith(self::ON_ITS_PORT . '?code=', self::string($response->headers->get('Location')));
        static::assertSame('state-of-the-client', self::redirectedQuery($response)['state']);
    }

    /**
     * RFC 6749 §4.1.3: the token request repeats the redirect URI of the authorization request, which is the
     * one the code was issued for, port included. The exception is at the authorization endpoint and nowhere
     * else: what the code holds is what was received, and the token endpoint compares byte for byte.
     */
    #[Test]
    public function theCodeIsExchangedOnThePortItWasIssuedFor(): void
    {
        // Given
        $code = $this->codeFor(self::ON_ITS_PORT);

        // When
        $this->exchange($code, self::ON_ITS_PORT);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertArrayHasKey('access_token', self::json($response));
    }

    /**
     * RFC 6749 §4.1.3: another port at the token endpoint is not the URI the code was issued for, so the
     * exception of the authorization endpoint does not follow the code there.
     */
    #[Test]
    public function theCodeIsNotExchangedOnAnotherPort(): void
    {
        // Given
        $code = $this->codeFor(self::ON_ITS_PORT);

        // When
        $this->exchange($code, 'http://127.0.0.1:8080/callback');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_grant', self::json($response)['error']);
    }

    /**
     * RFC 8252 §7.3: the port is the only thing that varies. Everything else is the exact match of
     * RFC 6749 §3.1.2.3, and a redirect URI that is not registered is never redirected to: the refusal is a
     * page (RFC 9700 §4.1).
     */
    #[Test]
    #[DataProvider('provideRefusedRedirectUris')]
    public function aRedirectUriThatIsNotTheRegisteredOneIsShownToTheUser(string $redirectUri): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', $this->authorizationUri($redirectUri));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
        static::assertStringContainsString('data-error="invalid_request"', self::string($response->getContent()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedRedirectUris(): iterable
    {
        yield 'another path on the port it was given' => ['http://127.0.0.1:53127/other'];
        yield 'a name in place of the literal' => ['http://localhost:53127/callback'];
        yield 'a private address' => ['http://192.168.1.10/callback'];
        yield 'the other loopback literal' => ['http://[::1]:53127/callback'];
        yield 'HTTPS on the literal' => ['https://127.0.0.1:53127/callback'];
    }

    /**
     * RFC 8252 §7.3: the exception belongs to a client that cannot register its port. A confidential client
     * has a host of its own and is held to what it registered, port included.
     */
    #[Test]
    public function aConfidentialClientIsHeldToItsRegisteredUri(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request(
            'GET',
            '/authorize?'
                . http_build_query(self::authorizationParameters('oidc-demo', [
                    'redirect_uri' => 'https://demo.test:8443/login/check',
                ])),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="invalid_request"', self::string($response->getContent()));
    }

    /**
     * The URI a native client registered is still the URI it registered: the exception adds a port and takes
     * nothing away.
     */
    #[Test]
    public function aNativeClientIsStillAnsweredOnTheUriItRegistered(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->allow(self::REGISTERED);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith(self::REGISTERED . '?code=', self::string($response->headers->get('Location')));
    }

    private function authorizationUri(string $redirectUri): string
    {
        return '/authorize?'
        . http_build_query(self::authorizationParameters('native-app', [
            'redirect_uri' => $redirectUri,
        ]));
    }

    /**
     * The authorization request of the native client, agreed to on the consent page: this client requires
     * one, being no first-party application of the deployment.
     */
    private function allow(string $redirectUri): void
    {
        $this->browser->request('GET', $this->authorizationUri($redirectUri));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $consent = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $this->browser->submit($consent->selectButton('Allow')->form());
    }

    /**
     * The code the native client gets once alice signed in and allowed, for the redirect URI given.
     */
    private function codeFor(string $redirectUri): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->allow($redirectUri);

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    private function exchange(string $code, string $redirectUri): void
    {
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'client_id' => 'native-app',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => self::CODE_VERIFIER,
        ]);
    }
}
