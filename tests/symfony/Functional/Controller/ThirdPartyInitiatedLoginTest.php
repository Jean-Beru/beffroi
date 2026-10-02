<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Oidc\Domain\Claims\SectorIdentifier;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\PairwiseSubjectRepositoryInterface;
use function http_build_query;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function rawurlencode;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §4, the two modules of the 3rd Party-Init OP plan: the "initiate_login_uri" a client
 * registers, refused in plain HTTP, and the login this provider begins at that client.
 *
 * The route is the half the plan does not judge. Both modules register a client and read its
 * registration back, and neither ever visits the URI it registered, so what holds the flow itself is
 * here and nowhere else.
 */
final class ThirdPartyInitiatedLoginTest extends BrowserTestCase
{
    private const string ROUTE = '/initiate-login';

    private const string INITIAL_ACCESS_TOKEN = 'a-value-the-tenant-handed-out';

    private const string INITIATE_LOGIN_URI = 'https://launched.test/start';

    private const string REDIRECT_URI = 'https://launched.test/callback';

    private const string ISSUED_BY_THIS_PROVIDER = '?iss=https%3A%2F%2Fop.test';

    /**
     * OIDC Core §4: the browser is sent to the URI the named client registered, carrying the issuer of
     * this provider, which is how that client knows which provider to have its user authenticate
     * against.
     */
    #[Test]
    public function theBrowserIsSentToTheClientNamingThisProvider(): void
    {
        // When
        $this->begin('launched-app');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame(self::INITIATE_LOGIN_URI . self::ISSUED_BY_THIS_PROVIDER, $response->headers->get('Location'));
    }

    /**
     * Architecture §5.2: a redirection of the interaction plane carries what every answer of that plane
     * carries, the referrer above all, which would otherwise tell the client which page of this provider
     * sent the browser.
     */
    #[Test]
    public function theRedirectionCarriesTheHeadersOfThePlane(): void
    {
        // When
        $this->begin('launched-app');

        // Then
        static::assertInteractionHeaders($this->browser->getResponse());
    }

    /**
     * The whole security of the route: a caller names a client, never a destination. A request carrying
     * URLs of its own is answered the one the client registered and nothing of what it sent.
     */
    #[Test]
    public function nothingOfTheRequestReachesTheClient(): void
    {
        // When
        $this->begin('launched-app', [
            'redirect_uri' => 'https://attacker.test/landing',
            'target_link_uri' => 'https://attacker.test/landing',
            'initiate_login_uri' => 'https://attacker.test/start',
            'url' => 'https://attacker.test/',
        ]);

        // Then
        static::assertSame(
            self::INITIATE_LOGIN_URI . self::ISSUED_BY_THIS_PROVIDER,
            $this->browser->getResponse()->headers->get('Location'),
        );
    }

    /**
     * A landing page registered by another client of the tenant is one this client never named, so it is
     * left out as any other is: the set a "target_link_uri" is drawn from is the registration of the
     * client being begun at.
     */
    #[Test]
    public function aLandingPageOfAnotherClientIsLeftOut(): void
    {
        // When
        $this->begin('launched-app', [
            'target_link_uri' => 'https://launched-pairwise.test/callback',
        ]);

        // Then
        static::assertSame(
            self::INITIATE_LOGIN_URI . self::ISSUED_BY_THIS_PROVIDER,
            $this->browser->getResponse()->headers->get('Location'),
        );
    }

    /**
     * OIDC Core §4: where the client is asked to land the user, carried because this client registered
     * it, byte for byte (RFC 6749 §3.1.2.3).
     */
    #[Test]
    public function aLandingPageTheClientRegisteredIsCarried(): void
    {
        // When
        $this->begin('launched-app', [
            'target_link_uri' => self::REDIRECT_URI,
        ]);

        // Then
        static::assertSame(
            self::INITIATE_LOGIN_URI . self::ISSUED_BY_THIS_PROVIDER . '&target_link_uri=' . rawurlencode(self::REDIRECT_URI),
            $this->browser->getResponse()->headers->get('Location'),
        );
    }

    /**
     * There is nothing to begin, and which of the two reasons it was is not said: a client no tenant of
     * this name holds, and one that registered no "initiate_login_uri", are one answer, so that asking
     * tells nobody which clients exist.
     */
    #[Test]
    #[DataProvider('provideNothingToBegin')]
    public function thereIsNoLoginToBegin(string $clientId): void
    {
        // When
        $this->begin($clientId);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_NOT_FOUND, $response->getStatusCode());
        static::assertStringContainsString('data-error="no_login_to_begin"', self::string($response->getContent()));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNothingToBegin(): iterable
    {
        yield 'a name no client of the tenant holds' => ['a-client-nobody-declared'];
        yield 'a client that registered no initiate_login_uri' => ['native-app'];
        yield 'no client named at all' => [''];
    }

    /**
     * OIDC Core §4: a browser that holds no session gives no hint and is sent on all the same. The
     * client is about to make an authorization request, and that request asks for whatever login it
     * needs; a provider that demanded one here would ask for it twice.
     */
    #[Test]
    public function aBrowserWithNoSessionIsSentOnWithNoHint(): void
    {
        // When
        $this->begin('launched-app');

        // Then
        static::assertArrayNotHasKey('login_hint', self::redirectedQuery($this->browser->getResponse()));
    }

    /**
     * OIDC Core §8 "public": a client that registers no kind sees the identifier the core keeps, so that
     * is what it is hinted with.
     */
    #[Test]
    public function theHintNamesTheSignedInUserAsTheClientSeesThem(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->begin('launched-app');

        // Then
        static::assertSame($alice->subject->value, self::redirectedQuery($this->browser->getResponse())['login_hint']);
    }

    /**
     * OIDC Core §8.1: a client that sees its users under a "sub" of its own sector is hinted with that
     * one, and the store names the user back under it. A provider that put the stable identifier here
     * would hand a pairwise client the one string pairwise exists to withhold, and would do it before
     * the client had asked for anything at all.
     */
    #[Test]
    public function aPairwiseClientIsHintedWithTheIdentifierOfItsOwnSector(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->begin('launched-pairwise-app');
        $hint = new Subject(self::redirectedQuery($this->browser->getResponse())['login_hint']);
        self::reload();
        $named = self::service('test.beffroi.pairwise_subjects', PairwiseSubjectRepositoryInterface::class)
            ->findUser(self::tenant(), new SectorIdentifier('launched-pairwise.test'), $hint);

        // Then
        static::assertNotSame($alice->subject->value, $hint->value);
        static::assertSame($alice->subject->value, $named?->subject->value);
    }

    /**
     * OIDCC-3rd_party-init-login: the registration answers the "initiate_login_uri" the client sent, and
     * the client configuration endpoint answers it again. Those two reads are the whole module.
     */
    #[Test]
    public function theRegistrationAndTheConfigurationEndpointBothAnswerTheUri(): void
    {
        // Given
        $this->issue();
        $registered = $this->register([
            'redirect_uris' => [self::REDIRECT_URI],
            'initiate_login_uri' => self::INITIATE_LOGIN_URI,
        ]);

        // When
        $this->browser->request('GET', self::string($registered['registration_client_uri']), server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . self::string($registered['registration_access_token']),
        ]);

        // Then
        static::assertSame(self::INITIATE_LOGIN_URI, $registered['initiate_login_uri']);
        static::assertSame(self::INITIATE_LOGIN_URI, self::json($this->browser->getResponse())['initiate_login_uri']);
    }

    /**
     * OIDCC-3rd_party-init-login-nohttps: OIDC Registration §2 makes it an "https" URL, and a
     * registration that sends any other is refused with the error and the status of RFC 7591 §3.2.2.
     *
     * The module sends the URL of the run with its scheme replaced, and the suite runs on
     * "localhost:8443": the member is held to "https" on the host a development stack is reached at as
     * well as on a name, which is the rule of no environment (issue #377).
     */
    #[Test]
    #[DataProvider('provideUrisInPlainHttp')]
    public function aUriInPlainHttpIsRefused(string $initiateLoginUri): void
    {
        // Given
        $this->issue();

        // When
        $this->send([
            'redirect_uris' => [self::REDIRECT_URI],
            'initiate_login_uri' => $initiateLoginUri,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertSame('invalid_client_metadata', self::json($response)['error']);
        static::assertStringContainsString('initiate_login_uri', self::string(self::json($response)['error_description']));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUrisInPlainHttp(): iterable
    {
        yield 'on the host the client registered' => ['http://launched.test/start'];
        yield 'on the loopback host the suite runs on' => ['http://localhost:8443/test/a/beffroi/initiate-login'];
    }

    /**
     * A client that registered itself is begun at like any other: what the route reads is a
     * registration, whatever wrote it.
     */
    #[Test]
    public function aClientThatRegisteredItselfIsBegunAtLikeAnyOther(): void
    {
        // Given
        $this->issue();
        $registered = $this->register([
            'redirect_uris' => [self::REDIRECT_URI],
            'initiate_login_uri' => self::INITIATE_LOGIN_URI,
        ]);

        // When
        $this->begin(self::string($registered['client_id']));

        // Then
        static::assertSame(
            self::INITIATE_LOGIN_URI . self::ISSUED_BY_THIS_PROVIDER,
            $this->browser->getResponse()->headers->get('Location'),
        );
    }

    /**
     * @param array<string, string> $parameters
     */
    private function begin(string $clientId, array $parameters = []): void
    {
        $this->browser->request('GET', self::ROUTE . '?' . http_build_query([
            'client_id' => $clientId,
        ] + $parameters));
    }

    private function issue(): void
    {
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
            ->save(new InitialAccessToken(
                Uuid::v7(),
                self::tenant(),
                DrawnSecret::digestOf(self::INITIAL_ACCESS_TOKEN),
                'The team that integrates',
                2,
                self::currentSecond(),
                self::currentSecond()->modify('+1 day'),
            ));
        self::reload();
    }

    /**
     * @param array<string, mixed> $members
     *
     * @return array<string, mixed>
     */
    private function register(array $members): array
    {
        $this->send($members);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
    }

    /**
     * @param array<string, mixed> $members
     */
    private function send(array $members): void
    {
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::INITIAL_ACCESS_TOKEN,
            ],
            content: json_encode(
                $members
                + [
                    'token_endpoint_auth_method' => 'client_secret_basic',
                ],
                JSON_THROW_ON_ERROR,
            ),
        );
    }
}
