<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use function base64_encode;
use Beffroi\Oidc\Tests\Fixture\AuthorizationDetailTypes;
use function http_build_query;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 9396: the "authorization_details" parameter over HTTP, end to end. A client registered for a type
 * asks for what it wants to do to what, the user reads it on the consent page and agrees, and the token
 * carries what they agreed to: in an "at+jwt" for the client registered for one shape, in the
 * introspection of the opaque token for the client registered for the other. One step per test, on the
 * test kernel, the "rar-app" and "rar-opaque-app" clients of its configuration and the one type it wires.
 */
final class RichAuthorizationRequestFlowTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'rar-app';

    private const string SECRET = 'rar-secret-of-at-least-32-characters-long';

    private const string REDIRECT_URI = 'https://rar.test/callback';

    private const string OPAQUE_CLIENT_ID = 'rar-opaque-app';

    private const string OPAQUE_SECRET = 'rar-opaque-secret-of-at-least-32-character';

    private const string OPAQUE_REDIRECT_URI = 'https://rar.test/opaque';

    /**
     * RFC 9396 §2: the consent page says what the detail asks for, in the words of its own type, which is
     * the part a user reads rather than recognises.
     */
    #[Test]
    public function theConsentPageSaysWhatTheDetailAsksFor(): void
    {
        // Given
        $interaction = $this->beginAuthorization(AuthorizationDetailTypes::parameter('acct-4711', ['read', 'write']));
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->consentPage($interaction);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame(
            [AuthorizationDetailTypes::INVENTED],
            $crawler->filter('li[data-authorization-detail]')->extract(['data-authorization-detail']),
        );
        static::assertStringContainsString('acct-4711', $crawler->filter('li[data-authorization-detail]')->text());
        static::assertStringContainsString('read, write', $crawler->filter('li[data-authorization-detail]')->text());
    }

    /**
     * RFC 9396 §7: the access token carries the details the user agreed to.
     */
    #[Test]
    public function theAccessTokenCarriesTheDetailsTheUserAgreedTo(): void
    {
        // Given
        $code = $this->codeAllowedByAlice(AuthorizationDetailTypes::parameter('acct-4711', ['read']));

        // When
        $this->exchange($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $claims = self::claimsOf(self::string(self::json($response)['access_token']));
        static::assertSame(
            [
                [
                    'type' => AuthorizationDetailTypes::INVENTED,
                    'account' => 'acct-4711',
                    'actions' => ['read'],
                ],
            ],
            $claims['authorization_details'],
        );
    }

    /**
     * RFC 9396 §7: the response says what it granted, which is where a client holding an opaque access token
     * learns it without introspecting its own token, and what any client compares with what it asked for.
     */
    #[Test]
    public function theTokenResponseSaysWhatItGranted(): void
    {
        // Given
        $code = $this->codeAllowedByAlice(AuthorizationDetailTypes::parameter('acct-4711', ['read']));

        // When
        $this->exchange($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame(
            [
                [
                    'type' => AuthorizationDetailTypes::INVENTED,
                    'account' => 'acct-4711',
                    'actions' => ['read'],
                ],
            ],
            self::json($response)['authorization_details'],
        );
    }

    /**
     * RFC 9396 §7: a response that granted nothing beyond its scopes writes no member at all.
     */
    #[Test]
    public function aTokenResponseThatGrantedNoDetailSaysNothingOfThem(): void
    {
        // Given
        $code = $this->codeAllowedByAlice(null);

        // When
        $this->exchange($code);

        // Then
        static::assertArrayNotHasKey('authorization_details', self::json($this->browser->getResponse()));
    }

    /**
     * RFC 9396 §7: a request that asks for nothing beyond its scopes gets a token that carries nothing of
     * one, rather than carrying it empty.
     */
    #[Test]
    public function aRequestThatAsksForNoDetailGetsATokenCarryingNone(): void
    {
        // Given
        $code = $this->codeAllowedByAlice(null);

        // When
        $this->exchange($code);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['access_token']));
        static::assertArrayNotHasKey('authorization_details', $claims);
    }

    /**
     * RFC 7662 §2.2, RFC 9396 §9: the introspection of an opaque token says what the claim of a
     * self-contained one would, so that a resource server learns the same thing from either shape.
     */
    #[Test]
    public function theIntrospectionOfAnOpaqueTokenSaysWhatTheUserAgreedTo(): void
    {
        // Given
        $accessToken = $this->opaqueAccessTokenAskedFor(AuthorizationDetailTypes::parameter('acct-0815', ['read']));

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
        static::assertSame(
            [
                [
                    'type' => AuthorizationDetailTypes::INVENTED,
                    'account' => 'acct-0815',
                    'actions' => ['read'],
                ],
            ],
            $members['authorization_details'],
        );
    }

    /**
     * RFC 9396 §5: a malformed array, an object naming no type, a type nobody serves, a type the client is
     * not registered for and a detail its own type refuses are each "invalid_authorization_details", which
     * reaches the client at its redirect URI.
     */
    #[Test]
    #[DataProvider('provideRefusedAuthorizationDetails')]
    public function anAuthorizationDetailsTheRequestCannotAskForIsRefused(string $authorizationDetails): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', $this->authorizationUri($authorizationDetails));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $query = self::redirectedQuery($response);
        static::assertSame('invalid_authorization_details', $query['error']);
        static::assertSame('state-of-the-client', $query['state']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideRefusedAuthorizationDetails(): iterable
    {
        yield 'not JSON' => ['[{'];
        yield 'a JSON object' => ['{"type":"account_information","account":"acct-4711"}'];
        yield 'an empty array' => ['[]'];
        yield 'an element naming no type' => ['[{"account":"acct-4711"}]'];
        yield 'a type nobody serves' => [AuthorizationDetailTypes::parameter(type: AuthorizationDetailTypes::UNSERVED)];
        yield 'a detail its own type refuses' => ['[{"type":"account_information","actions":["read"]}]'];
    }

    /**
     * RFC 9396 §11: a client that registered no type may ask for none, whatever the provider serves.
     */
    #[Test]
    public function aClientRegisteredForNoTypeIsRefused(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $query = http_build_query(self::authorizationParameters('native-app', [
            'authorization_details' => AuthorizationDetailTypes::parameter(),
        ]));

        // When
        $this->browser->request('GET', '/authorize?' . $query);

        // Then
        $query = self::redirectedQuery($this->browser->getResponse());
        static::assertSame('invalid_authorization_details', $query['error']);
    }

    /**
     * RFC 9396 §7: a token request narrows the details of the authorization it spends.
     */
    #[Test]
    public function aTokenRequestNarrowsTheDetailsOfTheAuthorization(): void
    {
        // Given
        $code = $this->codeAllowedByAlice(self::twoDetails());

        // When
        $this->exchange($code, [
            'authorization_details' => AuthorizationDetailTypes::parameter('acct-0815'),
        ]);

        // Then
        $claims = self::claimsOf(self::string(self::json($this->browser->getResponse())['access_token']));
        static::assertSame(
            [
                [
                    'type' => AuthorizationDetailTypes::INVENTED,
                    'account' => 'acct-0815',
                    'actions' => ['read'],
                ],
            ],
            $claims['authorization_details'],
        );
    }

    /**
     * RFC 9396 §7: and never widens them, even towards a type the client is registered for.
     */
    #[Test]
    public function aTokenRequestThatAsksForADetailTheAuthorizationDoesNotCarryIsRefused(): void
    {
        // Given
        $code = $this->codeAllowedByAlice(AuthorizationDetailTypes::parameter('acct-4711'));

        // When
        $this->exchange($code, [
            'authorization_details' => AuthorizationDetailTypes::parameter('acct-0815'),
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_authorization_details', self::json($response)['error']);
    }

    /**
     * RFC 9396 §7: the refresh token is bound to the whole of what the user agreed to, so a refresh may
     * ask for the detail the narrowed access token did not carry.
     */
    #[Test]
    public function aRefreshAsksForADetailTheNarrowedAccessTokenDidNotCarry(): void
    {
        // Given
        $code = $this->codeAllowedByAlice(self::twoDetails());
        $this->exchange($code, [
            'authorization_details' => AuthorizationDetailTypes::parameter('acct-4711'),
        ]);
        $refreshToken = self::string(self::json($this->browser->getResponse())['refresh_token']);

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'refresh_token',
                'refresh_token' => $refreshToken,
                'authorization_details' => AuthorizationDetailTypes::parameter('acct-0815'),
            ],
            server: self::credentials(self::CLIENT_ID, self::SECRET),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $claims = self::claimsOf(self::string(self::json($response)['access_token']));
        static::assertSame(self::detailOf('acct-0815'), $claims['authorization_details']);
    }

    /**
     * RFC 9396 §7: a request asking for more than the consent in force carries asks again, and the page
     * shows what is being added.
     */
    #[Test]
    public function aRequestAskingForMoreThanWasAgreedToAsksAgain(): void
    {
        // Given
        $this->codeAllowedByAlice(AuthorizationDetailTypes::parameter('acct-4711'));

        // When
        $this->browser->request('GET', $this->authorizationUri(AuthorizationDetailTypes::parameter('acct-0815')));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/consent?interaction=', self::string($response->headers->get('Location')));
    }

    /**
     * A request asking for no more than the consent in force carries is answered without a page.
     */
    #[Test]
    public function aRequestAskingForNoMoreThanWasAgreedToIsAnsweredAtOnce(): void
    {
        // Given
        $this->codeAllowedByAlice(AuthorizationDetailTypes::parameter('acct-4711'));

        // When
        $this->browser->request('GET', $this->authorizationUri(AuthorizationDetailTypes::parameter('acct-4711')));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertArrayHasKey('code', self::redirectedQuery($response));
    }

    /**
     * RFC 9126 §2: a request pushed to /par is read by the very parser the authorization endpoint reads
     * with, so the details it asks for travel with the record and reach the token.
     */
    #[Test]
    public function aPushedRequestCarriesTheDetailsItAsksFor(): void
    {
        // Given
        self::signingKey();
        $this->signIn(self::user('alice'));
        $pushed = self::authorizationParameters(self::OPAQUE_CLIENT_ID, [
            'redirect_uri' => self::OPAQUE_REDIRECT_URI,
            'authorization_details' => AuthorizationDetailTypes::parameter('acct-4711'),
        ]);
        $this->browser->request('POST', '/par', $pushed, server: self::credentials(self::OPAQUE_CLIENT_ID, self::OPAQUE_SECRET));
        $requestUri = self::string(self::json($this->browser->getResponse())['request_uri'] ?? null);

        // When
        $this->browser->request('GET', '/authorize', [
            'client_id' => self::OPAQUE_CLIENT_ID,
            'request_uri' => $requestUri,
        ]);
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
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
        $accessToken = self::string(self::json($this->browser->getResponse())['access_token']);
        $this->browser->request(
            'POST',
            '/introspect',
            [
                'token' => $accessToken,
            ],
            server: self::credentials(self::OPAQUE_CLIENT_ID, self::OPAQUE_SECRET),
        );

        // Then
        static::assertSame(self::detailOf('acct-4711'), self::json($this->browser->getResponse())['authorization_details']);
    }

    /**
     * RFC 9396 §10: the document announces the types the wiring gave the provider, so that a client knows
     * which "type" values exist at all.
     */
    #[Test]
    public function theDocumentAnnouncesTheTypesTheProviderServes(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        static::assertSame(
            [AuthorizationDetailTypes::INVENTED],
            self::json($this->browser->getResponse())['authorization_details_types_supported'],
        );
    }

    /**
     * The authorization request of the rich client, asking for the details given.
     */
    private function authorizationUri(?string $authorizationDetails, string $clientId = self::CLIENT_ID, string $redirectUri = self::REDIRECT_URI): string
    {
        $parameters = [
            'redirect_uri' => $redirectUri,
        ];
        if ($authorizationDetails !== null) {
            $parameters['authorization_details'] = $authorizationDetails;
        }

        return '/authorize?' . http_build_query(self::authorizationParameters($clientId, $parameters));
    }

    private function beginAuthorization(?string $authorizationDetails): string
    {
        self::signingKey();
        $this->browser->request('GET', $this->authorizationUri($authorizationDetails));

        return self::redirectedInteraction($this->browser->getResponse());
    }

    private function consentPage(string $interaction): Crawler
    {
        return $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
    }

    /**
     * The code the rich client gets once alice signed in and allowed what the request asked for.
     */
    private function codeAllowedByAlice(?string $authorizationDetails): string
    {
        $interaction = $this->beginAuthorization($authorizationDetails);
        $this->signIn(self::user('alice'));
        $this->browser->submit($this->consentPage($interaction)->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    /**
     * The opaque client requires no consent, so its code comes back from the authorization endpoint at once.
     */
    private function opaqueAccessTokenAskedFor(string $authorizationDetails): string
    {
        self::signingKey();
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', $this->authorizationUri($authorizationDetails, self::OPAQUE_CLIENT_ID, self::OPAQUE_REDIRECT_URI));
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
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
     * The one detail of the invented type, as a token carries it and an introspection renders it.
     *
     * @return list<array<string, mixed>>
     */
    private static function detailOf(string $account): array
    {
        return [
            [
                'type' => AuthorizationDetailTypes::INVENTED,
                'account' => $account,
                'actions' => ['read'],
            ],
        ];
    }

    /**
     * Two details of the one type the kernel serves, as a request writes them.
     */
    private static function twoDetails(): string
    {
        return '[{"type":"account_information","account":"acct-4711","actions":["read"]},{"type":"account_information","account":"acct-0815","actions":["read"]}]';
    }

    /**
     * @param array<string, string> $parameters
     */
    private function exchange(string $code, array $parameters = []): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ] + $parameters,
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
