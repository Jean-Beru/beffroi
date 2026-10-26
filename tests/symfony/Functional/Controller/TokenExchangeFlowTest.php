<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use function http_build_query;
use function rawurlencode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8693 over HTTP, end to end, and the chain the interoperability of this spike is judged on (issue
 * #228): a service asks the token endpoint for itself (RFC 6749 §4.4), a gateway exchanges that token to
 * act on its behalf, and what a resource server reads of the result is what the introspection endpoint
 * says of it: the subject is still the service, and "act" names the gateway.
 *
 * The walk of the lab (`castor demo --service`) plays the same chain against the running stack with a
 * Symfony resource server at the end of it; this is the provider's own side of it, on the test kernel, so
 * that what the walk drives is already known to answer.
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
     * RFC 8693 §2.2.1: the new token is about the same subject, and "act" says who holds it for that
     * subject. The gateway never becomes the subject: that is what tells a delegation from an
     * impersonation (§1.3).
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
     * RFC 8693 §2.2.1: the response says what it issued, and it is an access token of this provider.
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
     * RFC 8707 §2.2, RFC 8693 §2.1: nothing widens. The exchanged token is addressed to the resource the
     * exchange named, which is one of those the presented token was addressed to and no other.
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
     * RFC 7662 §2.2, RFC 8693 §4.1: the introspection of the exchanged token says the same thing the
     * self-contained one carries, so a resource server learns through whom it was reached whichever shape
     * it holds. It is the one place a resource server can read "act" at all when the token is opaque.
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
     * RFC 8693 §4.4: who may act for the subject of a token is what the registration of the client that
     * holds it says, and it is written on the token so that a resource server verifying it offline reads
     * the rule the provider applies.
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
     * RFC 8693 §2.1: what a client may present is a closed list on its registration, so a service that
     * registered no exchange at all cannot exchange the token it holds, whatever that token says.
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
     * RFC 6749 §3.3, RFC 8707 §2, RFC 6749 §5.2: what an exchange hands a gateway stays within what that
     * gateway registered. A presented token may carry more, the client it was issued to having registered
     * more, and a request that takes it all by naming nothing is answered with the error of the protocol for
     * what goes beyond, never with a server error.
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
     * The token a service holds for itself (RFC 6749 §4.4), addressed to the resource the exchange will
     * narrow to.
     */
    private function serviceToken(): string
    {
        return $this->clientToken(self::SERVICE_ID, self::SERVICE_SECRET);
    }

    /**
     * The token a client holds for itself (RFC 6749 §4.4), addressed to the resource the exchange narrows to.
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
     * The token a service holds for itself (RFC 6749 §4.4) for everything it registered, both scopes and both
     * resources, which is more than the gateway that acts for a person registered: one scope of the two and
     * one resource of the two.
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
     * RFC 8693 §2.1: the exchange of a delegation presents two tokens, the one it acts for and the one that
     * says who acts. The second is a token of the gateway itself, which is why it asks for one by
     * client_credentials before exchanging anything.
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

    /**
     * The token the gateway holds for itself, which it presents as the "actor_token" of the exchange.
     */
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
