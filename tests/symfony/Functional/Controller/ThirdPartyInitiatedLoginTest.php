<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

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
 * OIDC Core §4
 */
final class ThirdPartyInitiatedLoginTest extends BrowserTestCase
{
    private const string ROUTE = '/initiate-login';

    private const string INITIAL_ACCESS_TOKEN = 'a-value-the-tenant-handed-out';

    private const string INITIATE_LOGIN_URI = 'https://launched.test/start';

    private const string REDIRECT_URI = 'https://launched.test/callback';

    private const string ISSUED_BY_THIS_PROVIDER = '?iss=https%3A%2F%2Fop.test';

    /**
     * OIDC Core §4
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
     * Architecture §5.2
     */
    #[Test]
    public function theRedirectionCarriesTheHeadersOfThePlane(): void
    {
        // When
        $this->begin('launched-app');

        // Then
        static::assertInteractionHeaders($this->browser->getResponse());
    }

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
     * OIDC Core §4, RFC 6749 §3.1.2.3
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
     * OIDC Core §4
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
     * OIDC Core §8
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
     * OIDC Core §8.1
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
     * OIDC Core §8, decision 0006
     */
    #[Test]
    public function aClientThePersonGaveNoConsentIsSentNoHint(): void
    {
        // Given
        $this->issue();
        $registered = $this->register([
            'redirect_uris' => ['https://registered.test/callback'],
            'initiate_login_uri' => 'https://registered.test/start',
        ]);
        $this->signIn(self::user('alice'));

        // When
        $this->begin(self::string($registered['client_id']));

        // Then
        static::assertSame(
            'https://registered.test/start' . self::ISSUED_BY_THIS_PROVIDER,
            $this->browser->getResponse()->headers->get('Location'),
        );
    }

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
     * OIDC Registration §2, RFC 7591 §3.2.2
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
