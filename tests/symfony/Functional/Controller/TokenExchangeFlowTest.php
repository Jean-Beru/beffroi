<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use function http_build_query;
use function rawurlencode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8693, RFC 6749 §4.4
 */
final class TokenExchangeFlowTest extends BrowserTestCase
{
    private const string SERVICE_ID = 'service-app';

    private const string SERVICE_SECRET = 'service-secret-of-at-least-32-characters-l';

    private const string GATEWAY_ID = 'gateway-app';

    private const string GATEWAY_SECRET = 'gateway-secret-of-at-least-32-characters-l';

    private const string OPAQUE_SERVICE_ID = 'service-opaque-app';

    private const string OPAQUE_SERVICE_SECRET = 'service-opaque-secret-of-at-least-32-chars';

    private const string PERSON_GATEWAY_ID = 'person-gateway-app';

    private const string PERSON_GATEWAY_SECRET = 'person-gateway-secret-of-at-least-32-chara';

    private const string CALENDAR = 'https://cal.example.com/';

    private const string CONTACTS = 'https://contacts.example.com/';

    private const string ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

    /**
     * RFC 8693 §2.2.1, §1.3
     */
    #[Test]
    public function theExchangedTokenNamesTheServiceAndTheGatewayThatActsForIt(): void
    {
        // Given
        $subjectToken = $this->serviceToken();

        // When
        $this->exchange($subjectToken);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $claims = self::claimsOf(self::string(self::json($response)['access_token']));
        static::assertSame(self::SERVICE_ID, $claims['sub']);
        static::assertSame(self::GATEWAY_ID, $claims['client_id']);
        static::assertSame(
            [
                'sub' => self::GATEWAY_ID,
            ],
            $claims['act'],
        );
        static::assertSame(self::CALENDAR, $claims['aud']);
    }

    /**
     * RFC 8693 §2.2.1
     */
    #[Test]
    public function theExchangeSaysWhatItIssued(): void
    {
        // Given
        $subjectToken = $this->serviceToken();

        // When
        $this->exchange($subjectToken);

        // Then
        $body = self::json($this->browser->getResponse());
        static::assertSame(self::ACCESS_TOKEN_TYPE, $body['issued_token_type']);
        static::assertSame('Bearer', $body['token_type']);
        static::assertArrayNotHasKey('refresh_token', $body);
        static::assertArrayNotHasKey('id_token', $body);
    }

    /**
     * RFC 8707 §2.2, RFC 8693 §2.1
     */
    #[Test]
    public function theExchangeIsRefusedForAResourceThePresentedTokenWasNotAddressedTo(): void
    {
        // Given
        $subjectToken = $this->serviceToken();

        // When
        $this->exchange($subjectToken, self::CONTACTS);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_target', self::json($response)['error']);
    }

    /**
     * RFC 7662 §2.2, RFC 8693 §4.1
     */
    #[Test]
    public function theIntrospectionOfTheExchangedTokenNamesTheActor(): void
    {
        // Given
        $exchanged = $this->exchangedToken();

        // When
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $exchanged,
            ],
            server: self::credentials(self::GATEWAY_ID, self::GATEWAY_SECRET),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $members = self::json($response);
        static::assertTrue($members['active']);
        static::assertSame(self::SERVICE_ID, $members['sub']);
        static::assertSame(self::CALENDAR, $members['aud']);
        static::assertSame(
            [
                'sub' => self::GATEWAY_ID,
            ],
            $members['act'],
        );
    }

    /**
     * RFC 8693 §4.4
     */
    #[Test]
    public function theTokenOfTheServiceSaysWhoMayActForIt(): void
    {
        // When
        $subjectToken = $this->serviceToken();

        // Then
        static::assertSame(
            [
                'sub' => self::GATEWAY_ID,
            ],
            self::claimsOf($subjectToken)['may_act'],
        );
    }

    /**
     * RFC 8693 §2.1
     */
    #[Test]
    public function aClientThatRegisteredNoExchangeCannotExchangeAToken(): void
    {
        // Given
        $subjectToken = $this->serviceToken();

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token' => $subjectToken,
                'subject_token_type' => self::ACCESS_TOKEN_TYPE,
                'resource' => self::CALENDAR,
                'scope' => 'invoices.read',
            ],
            server: self::credentials(self::SERVICE_ID, self::SERVICE_SECRET),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('unauthorized_client', self::json($response)['error']);
    }

    /**
     * RFC 6749 §3.3, RFC 8707 §2, RFC 6749 §5.2
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideExchangesBeyondWhatTheGatewayRegistered')]
    public function anExchangeBeyondWhatTheGatewayRegisteredIsAnErrorOfTheProtocol(array $parameters, string $error): void
    {
        // Given
        $subjectToken = $this->tokenOfTheWholeRegistrationOfAService();

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token' => $subjectToken,
                'subject_token_type' => self::ACCESS_TOKEN_TYPE,
                ...$parameters,
            ],
            server: self::credentials(self::PERSON_GATEWAY_ID, self::PERSON_GATEWAY_SECRET),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame($error, self::json($response)['error']);
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function provideExchangesBeyondWhatTheGatewayRegistered(): iterable
    {
        yield 'a scope the gateway did not register, taken from the presented token' => [
            [
                'resource' => self::CALENDAR,
            ],
            'invalid_scope',
        ];
        yield 'a resource the gateway did not register, taken from the presented token' => [
            [
                'scope' => 'invoices.read',
            ],
            'invalid_target',
        ];
    }

    /**
     * RFC 6749 §4.4
     */
    private function serviceToken(): string
    {
        return $this->clientToken(self::SERVICE_ID, self::SERVICE_SECRET);
    }

    /**
     * RFC 6749 §4.4
     */
    private function clientToken(string $clientId, string $secret): string
    {
        self::signingKey();
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'client_credentials',
                'scope' => 'invoices.read',
                'resource' => self::CALENDAR,
            ],
            server: self::credentials($clientId, $secret),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['access_token']);
    }

    /**
     * RFC 6749 §4.4
     */
    private function tokenOfTheWholeRegistrationOfAService(): string
    {
        self::signingKey();
        $parameters = [
            'grant_type' => 'client_credentials',
            'scope' => 'invoices.read invoices.write',
        ];
        $this->browser->request(
            'POST',
            '/token',
            $parameters,
            [],
            self::credentials(self::OPAQUE_SERVICE_ID, self::OPAQUE_SERVICE_SECRET)
            + [
                'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
            ],
            http_build_query($parameters) . '&resource=' . rawurlencode(self::CALENDAR) . '&resource=' . rawurlencode(self::CONTACTS),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['access_token']);
    }

    /**
     * RFC 8693 §2.1
     */
    private function exchange(string $subjectToken, string $resource = self::CALENDAR): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token' => $subjectToken,
                'subject_token_type' => self::ACCESS_TOKEN_TYPE,
                'actor_token' => $this->gatewayToken(),
                'actor_token_type' => self::ACCESS_TOKEN_TYPE,
                'resource' => $resource,
                'scope' => 'invoices.read',
            ],
            server: self::credentials(self::GATEWAY_ID, self::GATEWAY_SECRET),
        );
    }

    private function gatewayToken(): string
    {
        return $this->clientToken(self::GATEWAY_ID, self::GATEWAY_SECRET);
    }

    private function exchangedToken(): string
    {
        $this->exchange($this->serviceToken());
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['access_token']);
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
