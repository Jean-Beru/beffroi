<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function http_build_query;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8252 §7.3
 */
final class LoopbackRedirectTest extends BrowserTestCase
{
    private const string REGISTERED = 'http://127.0.0.1/callback';

    private const string ON_ITS_PORT = 'http://127.0.0.1:53127/callback';

    /**
     * RFC 8252 §7.3
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
     * RFC 6749 §4.1.3
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
     * RFC 6749 §4.1.3
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
     * RFC 8252 §7.3, RFC 6749 §3.1.2.3, RFC 9700 §4.1
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
     * RFC 8252 §7.3
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

    private function allow(string $redirectUri): void
    {
        $this->browser->request('GET', $this->authorizationUri($redirectUri));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $consent = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $this->browser->submit($consent->selectButton('Allow')->form());
    }

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
