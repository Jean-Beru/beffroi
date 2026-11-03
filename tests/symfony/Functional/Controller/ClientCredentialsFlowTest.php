<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_filter;
use function base64_encode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 6749 §4.4 over HTTP, end to end: a service asks the token endpoint for itself, with no browser
 * anywhere and nobody signed in. The answer is an access token addressed to the resource it named and
 * nothing else, in an "at+jwt" for the "service-app" client of the test kernel and in the introspection of
 * the opaque one for "service-opaque-app". One step per test.
 */
final class ClientCredentialsFlowTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'service-app';

    private const string SECRET = 'service-secret-of-at-least-32-characters-l';

    private const string OPAQUE_CLIENT_ID = 'service-opaque-app';

    private const string OPAQUE_SECRET = 'service-opaque-secret-of-at-least-32-chars';

    private const string CALENDAR = 'https://cal.example.com/';

    /**
     * RFC 6749 §4.4.2, RFC 9068 §2.2, RFC 8707 §2: the token names the client in "sub" and in
     * "client_id", is addressed to the resource the request named, and says nothing of a sign-in.
     */
    #[Test]
    public function aServiceGetsATokenThatNamesItAndIsAddressedToItsResource(): void
    {
        // When
        $this->ask();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $claims = self::claimsOf(self::string(self::json($response)['access_token']));
        static::assertSame('https://op.test', $claims['iss']);
        static::assertSame(self::CLIENT_ID, $claims['sub']);
        static::assertSame(self::CLIENT_ID, $claims['client_id']);
        static::assertSame(self::CALENDAR, $claims['aud']);
        static::assertSame('invoices.read', $claims['scope']);
        static::assertArrayNotHasKey('sid', $claims);
        static::assertArrayNotHasKey('auth_time', $claims);
        static::assertArrayNotHasKey('acr', $claims);
        static::assertArrayNotHasKey('amr', $claims);
    }

    /**
     * RFC 6749 §4.4.3: an access token and nothing else, there being nobody to describe in an ID token and
     * no session to renew with a refresh token.
     */
    #[Test]
    public function theResponseCarriesNoIdTokenAndNoRefreshToken(): void
    {
        // When
        $this->ask([
            'scope' => 'invoices.read invoices.write',
        ]);

        // Then
        $parameters = self::json($this->browser->getResponse());
        static::assertSame('Bearer', $parameters['token_type']);
        static::assertSame('invoices.read invoices.write', $parameters['scope']);
        static::assertArrayNotHasKey('id_token', $parameters);
        static::assertArrayNotHasKey('refresh_token', $parameters);
    }

    /**
     * RFC 7662 §2.2, RFC 6749 §4.4: the introspection of the opaque shape says what the "at+jwt" says, the
     * client in "sub" and no sign-in.
     */
    #[Test]
    public function theIntrospectionOfTheOpaqueShapeSaysTheSameThing(): void
    {
        // Given
        $this->ask(client: self::OPAQUE_CLIENT_ID, secret: self::OPAQUE_SECRET);
        $accessToken = self::string(self::json($this->browser->getResponse())['access_token']);

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
        static::assertSame(self::OPAQUE_CLIENT_ID, $members['sub']);
        static::assertSame(self::OPAQUE_CLIENT_ID, $members['client_id']);
        static::assertSame(self::CALENDAR, $members['aud']);
        static::assertSame('invoices.read', $members['scope']);
        static::assertArrayNotHasKey('sid', $members);
        static::assertArrayNotHasKey('auth_time', $members);
        static::assertArrayNotHasKey('acr', $members);
        static::assertArrayNotHasKey('amr', $members);
    }

    /**
     * RFC 7009 §2.1: the opaque token of a service is taken back like any other, and is inactive after it.
     */
    #[Test]
    public function theOpaqueTokenOfAServiceIsRevokedLikeAnyOther(): void
    {
        // Given
        $this->ask(client: self::OPAQUE_CLIENT_ID, secret: self::OPAQUE_SECRET);
        $accessToken = self::string(self::json($this->browser->getResponse())['access_token']);

        // When
        $this->browser->request(
            'POST',
            '/revoke',
            [
                'token' => $accessToken,
            ],
            server: self::credentials(self::OPAQUE_CLIENT_ID, self::OPAQUE_SECRET),
        );

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
            ],
            server: self::credentials(self::OPAQUE_CLIENT_ID, self::OPAQUE_SECRET),
        );
        static::assertFalse(self::json($this->browser->getResponse())['active']);
    }

    /**
     * What this grant refuses, each with the error of RFC 6749 §5.2 or RFC 8707 §2 that says why, in JSON
     * and never a redirect.
     *
     * @param array<string, string|null> $parameters
     */
    #[Test]
    #[DataProvider('provideRequestsThisGrantRefuses')]
    public function aRequestThisGrantRefusesIsAnsweredWithItsError(array $parameters, string $error, int $status): void
    {
        // When
        $this->ask($parameters);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame($status, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame($error, self::json($response)['error']);
    }

    /**
     * @return iterable<string, array{array<string, string|null>, string, int}>
     */
    public static function provideRequestsThisGrantRefuses(): iterable
    {
        yield 'no resource (RFC 8707 §2)' => [
            [
                'resource' => null,
            ],
            'invalid_target',
            Response::HTTP_BAD_REQUEST,
        ];
        yield 'a resource the client did not register (RFC 8707 §2.1)' => [
            [
                'resource' => 'https://files.example.com/',
            ],
            'invalid_target',
            Response::HTTP_BAD_REQUEST,
        ];
        yield 'no scope' => [
            [
                'scope' => null,
            ],
            'invalid_request',
            Response::HTTP_BAD_REQUEST,
        ];
        yield 'the openid scope (OIDC Core §2)' => [
            [
                'scope' => 'openid',
            ],
            'invalid_scope',
            Response::HTTP_BAD_REQUEST,
        ];
        yield 'a scope the client did not register (RFC 6749 §3.3)' => [
            [
                'scope' => 'payroll.read',
            ],
            'invalid_scope',
            Response::HTTP_BAD_REQUEST,
        ];
    }

    /**
     * RFC 6749 §4.4: the client authenticates itself, so a request that proves nothing is invalid_client.
     */
    #[Test]
    public function aRequestThatDoesNotAuthenticateTheClientIsRefused(): void
    {
        // Given
        self::signingKey();

        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'client_credentials',
            'client_id' => self::CLIENT_ID,
            'scope' => 'invoices.read',
            'resource' => self::CALENDAR,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * RFC 6749 §4.4, OIDC Discovery §3: a client registered for another grant is not registered for this
     * one, and the endpoint says so before the grant reads anything.
     */
    #[Test]
    public function aClientNotRegisteredForThisGrantIsRefused(): void
    {
        // Given
        self::signingKey();

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'client_credentials',
                'scope' => 'invoices.read',
                'resource' => self::CALENDAR,
            ],
            server: self::credentials('oidc-demo', 'demo-secret-of-at-least-32-characters-long'),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('unauthorized_client', self::json($response)['error']);
    }

    /**
     * OIDC Discovery §3: the grant is announced because it is wired, and by nothing kept beside it.
     */
    #[Test]
    public function theDiscoveryDocumentAnnouncesTheGrant(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $announced = self::json($this->browser->getResponse())['grant_types_supported'] ?? null;
        static::assertIsArray($announced);
        static::assertContains('client_credentials', $announced);
    }

    /**
     * @param array<string, string|null> $parameters what replaces the defaults; null removes a parameter
     */
    private function ask(array $parameters = [], string $client = self::CLIENT_ID, string $secret = self::SECRET): void
    {
        self::signingKey();
        $body = [
            'grant_type' => 'client_credentials',
            'scope' => 'invoices.read',
            'resource' => self::CALENDAR,
            ...$parameters,
        ];
        $this->browser->request(
            'POST',
            '/token',
            array_filter($body, static fn (?string $value): bool => $value !== null),
            server: self::credentials($client, $secret),
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
