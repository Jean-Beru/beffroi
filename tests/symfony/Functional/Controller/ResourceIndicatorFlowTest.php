<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use function http_build_query;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function rawurlencode;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8707: the "resource" parameter over HTTP, end to end. A client registered for two resources asks
 * its tokens for one of them or for both, at the authorization endpoint and again at the token endpoint,
 * and the access token is addressed to what was asked: in an "at+jwt" for the client registered for one,
 * in the introspection of the opaque token for the client registered for the other. One step per test,
 * on the test kernel, the "resource-app" and "resource-opaque-app" clients of its configuration.
 */
final class ResourceIndicatorFlowTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'resource-app';

    private const string SECRET = 'resource-secret-of-at-least-32-characters';

    private const string REDIRECT_URI = 'https://resource.test/callback';

    private const string OPAQUE_CLIENT_ID = 'resource-opaque-app';

    private const string OPAQUE_SECRET = 'resource-opaque-secret-of-at-least-32-chars';

    private const string OPAQUE_REDIRECT_URI = 'https://resource.test/opaque';

    private const string CALENDAR = 'https://cal.example.com/';

    private const string CONTACTS = 'https://contacts.example.com/';

    /**
     * RFC 8707 §2, RFC 9068 §2.2: the token is addressed to the resource it was asked for, and
     * "client_id" goes on naming the client.
     */
    #[Test]
    public function theAccessTokenIsAddressedToTheResourceItWasAskedFor(): void
    {
        // Given
        $code = $this->codeAskedFor([self::CALENDAR]);

        // When
        $this->exchange($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $claims = self::claimsOf(self::string(self::json($response)['access_token']));
        static::assertSame(self::CALENDAR, $claims['aud']);
        static::assertSame(self::CLIENT_ID, $claims['client_id']);
    }

    /**
     * RFC 8707 §2.1: "resource" may be sent several times, and RFC 7519 §4.1.3 writes several audiences
     * as a list.
     */
    #[Test]
    public function aRequestThatNamesTwoResourcesGetsATokenAddressedToBoth(): void
    {
        // Given
        $code = $this->codeAskedFor([self::CALENDAR, self::CONTACTS]);

        // When
        $this->exchange($code);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['access_token']));
        static::assertSame([self::CALENDAR, self::CONTACTS], $claims['aud']);
    }

    /**
     * RFC 8707 §2: a request that names no resource asks for nothing beyond the provider itself, and
     * its token is addressed to the client, which is what every client of OpenID Connect gets.
     */
    #[Test]
    public function aRequestThatNamesNoResourceGetsATokenAddressedToItsClient(): void
    {
        // Given
        $code = $this->codeAskedFor([]);

        // When
        $this->exchange($code);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['access_token']));
        static::assertSame(self::CLIENT_ID, $claims['aud']);
    }

    /**
     * RFC 7662 §2.2, RFC 8707 §2: the introspection of an opaque token says what the "aud" of a
     * self-contained one would, so that a resource server learns the same thing from either shape.
     */
    #[Test]
    public function theIntrospectionOfAnOpaqueTokenSaysWhatItIsAddressedTo(): void
    {
        // Given
        $accessToken = $this->opaqueAccessTokenAskedFor([self::CONTACTS]);

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
            ],
            server: self::credentials(self::OPAQUE_CLIENT_ID, self::OPAQUE_SECRET),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $members = self::json($response);
        static::assertTrue($members['active']);
        static::assertSame(self::CONTACTS, $members['aud']);
        static::assertSame(self::OPAQUE_CLIENT_ID, $members['client_id']);
    }

    /**
     * RFC 8707 §2: a resource the client did not register, a relative URI and a URI with a fragment are
     * each "invalid_target", which reaches the client at its redirect URI.
     */
    #[Test]
    #[DataProvider('provideRefusedResources')]
    public function aResourceTheRequestCannotAskForIsRefused(string $resource): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', $this->authorizationUri([$resource]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $query = self::redirectedQuery($response);
        static::assertSame('invalid_target', $query['error']);
        static::assertSame('state-of-the-client', $query['state']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedResources(): iterable
    {
        yield 'a resource the client did not register' => ['https://files.example.com/'];
        yield 'a relative URI' => ['/calendar'];
        yield 'a URI with a fragment' => ['https://cal.example.com/#today'];
    }

    /**
     * RFC 8707 §2.2: a token request narrows the resources of the authorization it spends.
     */
    #[Test]
    public function aTokenRequestNarrowsTheResourcesOfTheAuthorization(): void
    {
        // Given
        $code = $this->codeAskedFor([self::CALENDAR, self::CONTACTS]);

        // When
        $this->exchange($code, [
            'resource' => self::CONTACTS,
        ]);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['access_token']));
        static::assertSame(self::CONTACTS, $claims['aud']);
    }

    /**
     * RFC 8707 §2.2: and never widens them, even towards a resource the client is registered for.
     */
    #[Test]
    public function aTokenRequestThatNamesAResourceTheAuthorizationDoesNotCarryIsRefused(): void
    {
        // Given
        $code = $this->codeAskedFor([self::CALENDAR]);

        // When
        $this->exchange($code, [
            'resource' => self::CONTACTS,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_target', self::json($response)['error']);
    }

    /**
     * RFC 8707 §2.1: "resource" may be sent several times, at the token endpoint as at the authorization
     * endpoint, and both values are read: the token endpoint reads a raw parameter the one way the whole
     * module reads one. The audience follows the order the token request named them, which is not the
     * order the authorization carries, so it is the request that was read and not the grant.
     */
    #[Test]
    public function aTokenRequestNamesAResourceTwiceAndBothAreRead(): void
    {
        // Given
        $code = $this->codeAskedFor([self::CALENDAR, self::CONTACTS]);

        // When
        $this->post(
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            'resource=' . rawurlencode(self::CONTACTS) . '&resource=' . rawurlencode(self::CALENDAR),
        );

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['access_token']));
        static::assertSame([self::CONTACTS, self::CALENDAR], $claims['aud']);
    }

    /**
     * RFC 6749 §3.1: every other parameter is single, and one the token endpoint receives twice is
     * "invalid_request" rather than read as whichever occurrence PHP kept.
     */
    #[Test]
    public function aParameterTheSpecificationSaysIsSingleIsRefusedWhenItIsSentTwice(): void
    {
        // Given
        $code = $this->codeAskedFor([self::CALENDAR]);

        // When
        $this->post(
            '/token',
            [
                'grant_type' => 'authorization_code',
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            'code=' . rawurlencode($code) . '&code=' . rawurlencode($code),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_request', self::json($response)['error']);
    }

    /**
     * RFC 8707 §2.2: the refresh token is bound to the full original grant, so a refresh may ask for
     * the resource the access token beside it was not narrowed to.
     */
    #[Test]
    public function aRefreshAsksForAResourceTheNarrowedAccessTokenDidNotCarry(): void
    {
        // Given
        $code = $this->codeAskedFor([self::CALENDAR, self::CONTACTS]);
        $this->exchange($code, [
            'resource' => self::CALENDAR,
        ]);
        $refreshToken = self::string(self::json($this->browser->getResponse())['refresh_token']);

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'resource' => self::CONTACTS,
            ],
            server: self::credentials(self::CLIENT_ID, self::SECRET),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $claims = self::claimsOf(self::string(self::json($response)['access_token']));
        static::assertSame(self::CONTACTS, $claims['aud']);
    }

    /**
     * RFC 9126 §2, RFC 8707 §2.1: a request pushed to /par is read by the very parser the authorization
     * endpoint reads with, so the resources it names travel with the record and reach the token.
     */
    #[Test]
    public function aPushedRequestCarriesTheResourcesItNames(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $pushed = self::authorizationParameters(self::CLIENT_ID, [
            'redirect_uri' => self::REDIRECT_URI,
        ]);
        $body = http_build_query($pushed) . '&resource=' . rawurlencode(self::CALENDAR) . '&resource=' . rawurlencode(self::CONTACTS);
        $this->browser->request(
            'POST',
            '/par',
            $pushed,
            [],
            self::credentials(self::CLIENT_ID, self::SECRET)
            + [
                'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
            ],
            $body,
        );
        $requestUri = self::string(self::json($this->browser->getResponse())['request_uri'] ?? null);

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => self::CLIENT_ID,
            'request_uri' => $requestUri,
        ]);
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
        $this->exchange($code);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['access_token']));
        static::assertSame([self::CALENDAR, self::CONTACTS], $claims['aud']);
    }

    /**
     * RFC 8707 §2: a token addressed to a resource opens nothing of the provider itself, the UserInfo
     * endpoint included; a client that comes for the claims of its user asks for a token naming no
     * resource.
     */
    #[Test]
    public function aTokenAddressedToAResourceOpensNothingOfTheProvider(): void
    {
        // Given
        $code = $this->codeAskedFor([self::CALENDAR]);
        $this->exchange($code);
        $accessToken = self::string(self::json($this->browser->getResponse())['access_token']);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertStringContainsString('error="invalid_token"', self::string($response->headers->get('WWW-Authenticate')));
    }

    /**
     * RFC 9728 §4: the document enumerates the resources the clients of the tenant registered, so that
     * a client knows which "resource" values exist at all.
     */
    #[Test]
    public function theDocumentEnumeratesTheResourcesOfTheTenant(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertSame([self::CALENDAR, self::CONTACTS], self::json($this->browser->getResponse())['protected_resources']);
    }

    /**
     * The authorization request of the resource client, with the resources named once each; a repeated
     * parameter is written by hand, an array of query parameters being unable to carry one.
     *
     * @param list<string> $resources
     */
    private function authorizationUri(array $resources, string $clientId = self::CLIENT_ID, string $redirectUri = self::REDIRECT_URI): string
    {
        $query = http_build_query(self::authorizationParameters($clientId, [
            'redirect_uri' => $redirectUri,
        ]));
        foreach ($resources as $resource) {
            $query .= '&resource=' . rawurlencode($resource);
        }

        return '/authorize?' . $query;
    }

    /**
     * The code the resource client gets once alice signed in, the request having asked for the
     * resources given.
     *
     * @param list<string> $resources
     */
    private function codeAskedFor(array $resources, string $clientId = self::CLIENT_ID, string $redirectUri = self::REDIRECT_URI): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', $this->authorizationUri($resources, $clientId, $redirectUri));

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    /**
     * @param list<string> $resources
     */
    private function opaqueAccessTokenAskedFor(array $resources): string
    {
        $code = $this->codeAskedFor($resources, self::OPAQUE_CLIENT_ID, self::OPAQUE_REDIRECT_URI);
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::OPAQUE_REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: self::credentials(self::OPAQUE_CLIENT_ID, self::OPAQUE_SECRET),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['access_token']);
    }

    /**
     * A form body written by hand, which is the only way to send a name twice over HTTP: PHP keeps the
     * last occurrence of a repeated name and says nothing of the others.
     *
     * @param array<string, string> $parameters the names the body carries once
     * @param string $repeated what it carries besides them, already encoded
     */
    private function post(string $uri, array $parameters, string $repeated): void
    {
        $this->browser->request(
            'POST',
            $uri,
            $parameters,
            [],
            self::credentials(self::CLIENT_ID, self::SECRET)
            + [
                'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
            ],
            http_build_query($parameters) . '&' . $repeated,
        );
    }

    /**
     * The token request of the resource client, the body written by hand so that a "resource" it names
     * twice reaches the endpoint as the two values it is.
     *
     * @param array<string, string|list<string>> $parameters
     */
    private function exchange(string $code, array $parameters = []): void
    {
        $body = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::REDIRECT_URI,
            'code_verifier' => self::CODE_VERIFIER,
        ];
        $this->browser->request(
            'POST',
            '/token',
            $body + $parameters,
            server: self::credentials(self::CLIENT_ID, self::SECRET),
        );
    }

    /**
     * @return array<string, string>
     */
    private static function credentials(string $clientId, string $secret): array
    {
        return [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
        ];
    }
}
