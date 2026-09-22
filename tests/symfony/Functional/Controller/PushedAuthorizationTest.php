<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Heidi\Oidc\Domain\PushedAuthorization\RequestUri;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 9126 and architecture §4.2: the whole way through the stack, from the request a client pushes at
 * /par to the code the browser carries back, with the module behind Doctrine. The authorization request
 * never travels through the browser, which is the first requirement of FAPI 2.0.
 */
final class PushedAuthorizationTest extends BrowserTestCase
{
    /**
     * The client of the test kernel that may still start an ordinary request, so that the two ways are
     * told apart.
     */
    private const string CLIENT = 'oidc-demo';

    private const string SECRET = 'demo-secret-of-at-least-32-characters-long';

    private const string REDIRECT_URI = 'https://demo.test/login/check';

    /**
     * RFC 9126 §2: POST only.
     */
    #[Test]
    public function theEndpointIsPostOnly(): void
    {
        // When
        $this->browser->request('GET', '/par', self::pushedParameters());

        // Then
        static::assertSame(Response::HTTP_METHOD_NOT_ALLOWED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 9126 §2.2: a 201, the reference of the registered URN and its lifetime, never cached.
     */
    #[Test]
    public function aPushedRequestIsAnsweredWithAReferenceThatIsNeverCached(): void
    {
        // When
        $this->push();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('no-cache', $response->headers->get('Pragma'));
        $answer = self::json($response);
        static::assertStringStartsWith(RequestUri::URN_PREFIX, self::string($answer['request_uri'] ?? null));
        static::assertSame(60, $answer['expires_in'] ?? null);
    }

    /**
     * RFC 9126 §4: the reference and the client identifier are the whole authorization request, and the
     * browser goes on as it would have from an ordinary one.
     */
    #[Test]
    public function aPushedRequestIsUsedOnceAndSendsTheBrowserOn(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => self::CLIENT,
            'request_uri' => $requestUri,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?interaction=', self::string($response->headers->get('Location')));
    }

    /**
     * RFC 9126 §4: "the client MUST only use a request_uri value once", and the provider holds it to it.
     */
    #[Test]
    public function aReferenceIsReadAgainWhileNobodyHasAnsweredTheRequest(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();
        $this->authorize($requestUri);

        // When
        $this->authorize($requestUri);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?interaction=', self::string($response->headers->get('Location')));
    }

    /**
     * RFC 9126 §4: the reference is spent by the code it buys, and grants nothing afterwards.
     */
    #[Test]
    public function aReferenceIsRefusedOnceTheRequestItCarriedWasGranted(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();
        $this->authorize($requestUri);
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/login', [
            'interaction' => self::redirectedInteraction($this->browser->getResponse()),
        ]);
        static::assertStringStartsWith(self::REDIRECT_URI . '?code=', self::string($this->browser->getResponse()->headers->get('Location')));

        // When
        $this->authorize($requestUri);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('invalid_request_uri', self::string($response->getContent()));
    }

    /**
     * RFC 9126 §4: "An expired request_uri MUST be rejected as invalid".
     */
    #[Test]
    public function aReferencePastItsLifetimeIsRefused(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();
        self::mockTime('+61 seconds');

        // When
        $this->authorize($requestUri);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 9126 §2.2: "The request_uri value MUST be bound to the client that posted the authorization
     * request".
     */
    #[Test]
    public function aReferencePresentedByAnotherClientIsRefused(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri();

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'native-app',
            'request_uri' => $requestUri,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * RFC 9126 §4: the parameters the endpoint reads are the ones that were pushed; the query carries
     * the client and the reference, and whatever else it carries is dropped.
     */
    #[Test]
    public function theQueryNeverContradictsWhatWasPushed(): void
    {
        // Given
        $requestUri = $this->pushedRequestUri([
            'scope' => 'openid profile',
            'state' => 'state-of-the-client',
        ]);

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => self::CLIENT,
            'request_uri' => $requestUri,
            'scope' => 'openid email',
            'state' => 'state-of-the-attacker',
        ]);
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/login', [
            'interaction' => self::redirectedInteraction($this->browser->getResponse()),
        ]);

        // Then
        $query = self::redirectedQuery($this->browser->getResponse());
        static::assertSame('state-of-the-client', $query['state']);
        static::assertStringStartsWith(self::REDIRECT_URI . '?code=', self::string($this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * RFC 9126 §6: a client that only starts its requests by pushing them is refused an ordinary one,
     * on a page, before anything of the request is read.
     */
    #[Test]
    public function aClientThatMustPushIsRefusedAnOrdinaryRequest(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('fapi-app', [
            'redirect_uri' => 'https://fapi.test/callback',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertNull($response->headers->get('Location'));
    }

    /**
     * RFC 9126 §6: the very same request, pushed, is served.
     */
    #[Test]
    public function theSameClientIsServedOnceItHasPushedItsRequest(): void
    {
        // Given
        $this->browser->request(
            'POST',
            '/par',
            self::pushedParameters([
                'client_id' => 'fapi-app',
                'redirect_uri' => 'https://fapi.test/callback',
            ]),
            [],
            [
                'HTTP_AUTHORIZATION' => self::basic('fapi-app', 'fapi-secret-of-at-least-32-characters-long'),
            ],
        );
        $requestUri = self::string(self::json($this->browser->getResponse())['request_uri'] ?? null);

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => 'fapi-app',
            'request_uri' => $requestUri,
        ]);

        // Then
        static::assertStringStartsWith('/login?interaction=', self::string($this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * RFC 9126 §2.3: what the endpoint refuses is a JSON error, never a redirection, even when the
     * request names a redirect URI the provider would otherwise have answered to.
     */
    #[Test]
    public function aRefusalAtTheEndpointNeverRedirects(): void
    {
        // When
        $this->push([
            'scope' => 'openid banking',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertNull($response->headers->get('Location'));
        static::assertSame('invalid_scope', self::json($response)['error'] ?? null);
    }

    /**
     * RFC 9126 §2: the client is authenticated exactly as at the token endpoint, and a wrong secret is
     * refused with the challenge of RFC 6749 §5.2.
     */
    #[Test]
    public function aClientThatDoesNotAuthenticateIsRefused(): void
    {
        // When
        $this->browser->request(
            'POST',
            '/par',
            self::pushedParameters(),
            [],
            [
                'HTTP_AUTHORIZATION' => self::basic(self::CLIENT, 'not-the-secret'),
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error'] ?? null);
    }

    /**
     * OIDC Discovery §3 and RFC 9126 §5: the document names the endpoint, and says the provider takes an
     * ordinary request because a client of the tenant may still start one.
     */
    #[Test]
    public function theMetadataAnnouncesTheEndpoint(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $metadata = self::json($this->browser->getResponse());
        static::assertSame('https://op.test/par', $metadata['pushed_authorization_request_endpoint'] ?? null);
        static::assertFalse($metadata['require_pushed_authorization_requests'] ?? null);
    }

    /**
     * @param array<string, string|null> $parameters
     */
    private function push(array $parameters = []): void
    {
        $this->browser->request(
            'POST',
            '/par',
            self::pushedParameters($parameters),
            [],
            [
                'HTTP_AUTHORIZATION' => self::basic(self::CLIENT, self::SECRET),
            ],
        );
    }

    /**
     * @param array<string, string|null> $parameters
     */
    private function pushedRequestUri(array $parameters = []): string
    {
        $this->push($parameters);

        return self::string(self::json($this->browser->getResponse())['request_uri'] ?? null);
    }

    private function authorize(string $requestUri): void
    {
        $this->browser->request('GET', '/authorize', [
            'client_id' => self::CLIENT,
            'request_uri' => $requestUri,
        ]);
    }

    /**
     * @param array<string, string|null> $parameters
     *
     * @return array<string, string>
     */
    private static function pushedParameters(array $parameters = []): array
    {
        return self::authorizationParameters(
            self::CLIENT,
            $parameters
            + [
                'redirect_uri' => self::REDIRECT_URI,
            ],
        );
    }

    private static function basic(string $clientId, string $secret): string
    {
        return 'Basic ' . base64_encode($clientId . ':' . $secret);
    }
}
