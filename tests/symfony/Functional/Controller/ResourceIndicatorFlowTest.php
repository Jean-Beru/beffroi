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
 * RFC 8707
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
     * RFC 8707 §2, RFC 9068 §2.2
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
     * RFC 8707 §2.1, RFC 7519 §4.1.3
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
     * RFC 8707 §2
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
     * RFC 7662 §2.2, RFC 8707 §2
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
     * RFC 8707 §2
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
     * RFC 8707 §2.2
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
     * RFC 8707 §2.2
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
     * RFC 8707 §2.1
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
     * RFC 6749 §3.1
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
     * RFC 8707 §2.2
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
     * RFC 9126 §2, RFC 8707 §2.1
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
     * RFC 8707 §2
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
     * RFC 9728 §4
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
     * A body written by hand: an array of parameters cannot repeat a name.
     *
     * @param array<string, string> $parameters
     * @param string $repeated already encoded
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
