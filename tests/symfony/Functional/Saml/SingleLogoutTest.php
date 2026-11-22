<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use App\Key\KmsUnavailableListener;
use App\Saml\SamlSigning;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use App\Tests\Symfony\Functional\Controller\TokensOfASession;
use App\Tests\Symfony\Functional\Key\KmsOutage;
use App\Tests\Symfony\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\ReceivedLogoutResponse;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\AcceptedLogoutResponse;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\LogoutResponseValidator;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Writing\Signing;
use function array_map;
use Closure;
use function explode;
use function parse_url;
use function sprintf;
use const PHP_URL_HOST;
use const PHP_URL_PATH;
use const PHP_URL_QUERY;
use const PHP_URL_SCHEME;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md section 6.5
 */
final class SingleLogoutTest extends ConsoleTestCase
{
    use TokensOfASession;

    private const string SERVICE_PROVIDER = ServiceProviderDocuments::SIGNED;

    private const string ASSERTION_CONSUMER = ServiceProviderDocuments::SIGNED . '/acs';

    private const string SINGLE_LOGOUT = ServiceProviderDocuments::SIGNED . '/slo';

    private const string SINGLE_LOGOUT_POST = ServiceProviderDocuments::SIGNED . '/slo/post';

    private const string SINGLE_SIGN_ON = 'https://op.test/saml/sso';

    private const string IDENTITY_PROVIDER_SINGLE_LOGOUT = 'https://op.test/saml/slo';

    private const string LOGOUT_REQUEST_ID = '_0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b';

    /**
     * spec/saml.md section 6.8
     */
    private const string POLICY = "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; form-action %s; base-uri 'none'; frame-ancestors 'none'";

    private User $alice;

    private KmsOutage $kms;

    protected function setUp(): void
    {
        $this->kms = new KmsOutage();
        parent::setUp();
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedServiceProviderMetadata(
                Uuid::v7(),
                self::tenant(),
                self::SERVICE_PROVIDER,
                ServiceProviderDocuments::exampleOrgWithSingleLogout([
                    [Binding::HttpRedirect->value, self::SINGLE_LOGOUT, null],
                    [Binding::HttpPost->value, self::SINGLE_LOGOUT_POST, null],
                ]),
                null,
                self::currentSecond(),
            ));
        $this->alice = self::userWithPassword('alice', 'correct horse battery staple');
    }

    protected function configureContainer(): Closure
    {
        return $this->kms->takeOver(...);
    }

    /**
     * S-22, S-27, B-12
     */
    #[Test]
    public function aLogoutOverHttpRedirectIsAnsweredSuccessAtTheSingleLogoutService(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, StatusCode::Success],
            [$response->getStatusCode(), $this->answer($response->headers->get('Location') ?? '')[0]->response->status->code],
        );
    }

    /**
     * B-9, section 6.8
     */
    #[Test]
    public function theRelayStateComesBackWithTheAnswer(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        static::assertSame('state-2', $this->answer($this->browser->getResponse()->headers->get('Location') ?? '')[1]);
    }

    /**
     * SAML Bindings §3.4.5.1
     */
    #[Test]
    public function theRedirectionCarriesTheCachingOfTheBinding(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [true, true, 'no-cache'],
            [
                $response->headers->hasCacheControlDirective('no-store'),
                $response->headers->hasCacheControlDirective('no-cache'),
                $response->headers->get('Pragma'),
            ],
        );
    }

    /**
     * S-24, S-25
     */
    #[Test]
    public function theSessionOfTheProviderEnds(): void
    {
        // Given
        $assertion = $this->signedOn();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        static::assertSame(SessionEnd::RelyingParty, $this->sessionOf($assertion)->endedBy);
    }

    /**
     * S-25, Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientOfOpenIdConnectOfTheSessionIsToldByTheBackChannel(): void
    {
        // Given
        $assertion = $this->signedOn();
        self::signingKey();
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        $told = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof LogoutTokenIssued) {
                $told[] = [$event->clientId, $event->sessionId->toRfc4122()];
            }
        }
        static::assertSame([['oidc-demo', self::sessionIndex($assertion)]], $told);
    }

    /**
     * S-25
     */
    #[Test]
    public function theTokensIssuedUnderTheSessionAreRevoked(): void
    {
        // Given
        $assertion = $this->signedOn();
        $tokens = self::tokensIssuedIn($this->sessionOf($assertion));

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        self::assertTheTokensAreRevoked($tokens);
    }

    /**
     * S-25
     */
    #[Test]
    public function theBrowserIsSignedOut(): void
    {
        // Given
        $assertion = $this->signedOn();
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // When
        $this->browser->request(
            'GET',
            self::pathOf(new RedirectSender()->authnRequest(self::authnRequest('_5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c'), self::signing(), 'state-3')),
        );

        // Then
        static::assertSame(
            [Response::HTTP_FOUND, '/login'],
            [$this->browser->getResponse()->getStatusCode(), parse_url($this->browser->getResponse()->headers->get('Location') ?? '', PHP_URL_PATH)],
        );
    }

    /**
     * S-27, M-2
     */
    #[Test]
    public function aLogoutOverHttpPostIsAnsweredWithThePageThatPostsTheResponse(): void
    {
        // Given
        $assertion = $this->signedOn();
        $form = new PostSender()->logoutRequest($this->logoutRequest($assertion), self::signing(), 'state-2');

        // When
        $this->browser->request('POST', '/saml/slo', $form->fields, [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded']);

        // Then
        $posted = $this->form();
        $response = new PostReceiver(SamlLoader::create())->logoutMessage($posted['fields']);
        static::assertInstanceOf(ReceivedLogoutResponse::class, $response);
        static::assertSame(
            [self::SINGLE_LOGOUT_POST, StatusCode::Success],
            [$posted['action'], $this->validated($response, self::SINGLE_LOGOUT_POST)->response->status->code],
        );
    }

    /**
     * S-36, section 6.8
     */
    #[Test]
    public function thePagePostingTheResponseNamesTheOriginOfItsActionAloneInItsPolicy(): void
    {
        // Given
        $assertion = $this->signedOn();
        $form = new PostSender()->logoutRequest($this->logoutRequest($assertion), self::signing(), 'state-2');

        // When
        $this->browser->request('POST', '/saml/slo', $form->fields, [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded']);

        // Then
        static::assertSame(
            sprintf(self::POLICY, 'https://sp.example.org'),
            $this->browser->getResponse()->headers->get('Content-Security-Policy'),
        );
    }

    /**
     * S-23
     */
    #[Test]
    public function theSameLogoutRequestIsRefusedTheSecondTime(): void
    {
        // Given
        $url = self::pathOf($this->logoutUrl($this->signedOn()));
        $this->browser->request('GET', $url);

        // When
        $this->browser->request('GET', $url);

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 1],
            [$this->browser->getResponse()->getStatusCode(), $this->browser->getCrawler()->filter('[data-error="saml_logout_refused"]')->count()],
        );
    }

    /**
     * S-22, M-2
     */
    #[Test]
    public function anUnsignedLogoutRequestIsRefused(): void
    {
        // Given
        $assertion = $this->signedOn();
        [$unsigned] = explode('&SigAlg=', self::pathOf($this->logoutUrl($assertion)));

        // When
        $this->browser->request('GET', $unsigned);

        // Then
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, false],
            [$this->browser->getResponse()->getStatusCode(), $this->sessionOf($assertion)->hasEnded()],
        );
    }

    /**
     * S-25, S-27, section 6.5 step 1
     */
    #[Test]
    public function aTenantWithoutItsKeyEndsNoSession(): void
    {
        // Given
        $assertion = $this->signedOn();
        self::withoutActiveKey();

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        static::assertSame(
            [Response::HTTP_NOT_FOUND, false],
            [$this->browser->getResponse()->getStatusCode(), $this->sessionOf($assertion)->hasEnded()],
        );
    }

    /**
     * S-23, section 6.5 step 1
     */
    #[Test]
    public function theSameRequestIsAnsweredOnceTheKeyIsBack(): void
    {
        // Given
        $url = self::pathOf($this->logoutUrl($this->signedOn()));
        self::withoutActiveKey();
        $this->browser->request('GET', $url);
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        // When
        $this->browser->request('GET', $url);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, StatusCode::Success],
            [$response->getStatusCode(), $this->answer($response->headers->get('Location') ?? '')[0]->response->status->code],
        );
    }

    /**
     * S-25, S-27, section 6.5 step 1, Architecture §5.4
     */
    #[Test]
    public function aKmsThatDoesNotAnswerEndsNoSession(): void
    {
        // Given
        $assertion = $this->signedOn();
        self::withAKeyNotOpenedYet();
        $this->kms->down = true;

        // When
        $this->browser->request('GET', self::pathOf($this->logoutUrl($assertion)));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_SERVICE_UNAVAILABLE, (string) KmsUnavailableListener::RETRY_AFTER, false],
            [$response->getStatusCode(), $response->headers->get('Retry-After'), $this->sessionOf($assertion)->hasEnded()],
        );
    }

    /**
     * S-23, section 6.5 step 1
     */
    #[Test]
    public function theSameRequestIsAnsweredOnceTheKmsIsBack(): void
    {
        // Given
        $url = self::pathOf($this->logoutUrl($this->signedOn()));
        self::withAKeyNotOpenedYet();
        $this->kms->down = true;
        $this->browser->request('GET', $url);
        $this->kms->down = false;

        // When
        $this->browser->request('GET', $url);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, StatusCode::Success],
            [$response->getStatusCode(), $this->answer($response->headers->get('Location') ?? '')[0]->response->status->code],
        );
    }

    /**
     * S-26
     */
    #[Test]
    public function theSignOnRecordsTheServiceProviderOfTheSession(): void
    {
        // When
        $assertion = $this->signedOn();

        // Then
        static::assertSame(
            [self::SERVICE_PROVIDER],
            array_map(
                static fn (SessionParticipation $participation): string => $participation->serviceProvider,
                self::service('test.beffroi.saml_session_participants', SessionParticipationRepositoryInterface::class)
                    ->ofSession(Uuid::fromString(self::sessionIndex($assertion))),
            ),
        );
    }

    private function signedOn(): AcceptedAssertion
    {
        $this->signIn($this->alice);
        $this->browser->request('GET', self::pathOf(new RedirectSender()->authnRequest(self::authnRequest(), self::signing(), 'state-1')));
        $form = $this->form();
        static::assertSame(self::ASSERTION_CONSUMER, $form['action']);

        return new PostReceiver(SamlLoader::create())
            ->response($form['fields'])
            ->validate(
                new ResponseValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
                $this->identityProvider(),
                ExpectedResponse::toRequest('_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b', self::ASSERTION_CONSUMER, self::SERVICE_PROVIDER),
            );
    }

    private function logoutRequest(AcceptedAssertion $assertion): LogoutRequest
    {
        $nameId = $assertion->assertion->nameId;

        return new LogoutRequest(
            self::LOGOUT_REQUEST_ID,
            self::currentSecond(),
            new Issuer(self::SERVICE_PROVIDER),
            self::IDENTITY_PROVIDER_SINGLE_LOGOUT,
            null,
            new NameId($nameId->value, $nameId->format, $nameId->nameQualifier, $nameId->spNameQualifier),
            [self::sessionIndex($assertion)],
        );
    }

    private function logoutUrl(AcceptedAssertion $assertion): string
    {
        return new RedirectSender()->logoutRequest($this->logoutRequest($assertion), self::signing(), 'state-2');
    }

    /**
     * @return array{AcceptedLogoutResponse, ?string} the response and its RelayState
     */
    private function answer(string $location): array
    {
        static::assertSame(
            self::SINGLE_LOGOUT,
            parse_url($location, PHP_URL_SCHEME) . '://' . parse_url($location, PHP_URL_HOST) . parse_url($location, PHP_URL_PATH),
        );
        $received = new RedirectReceiver(SamlLoader::create())->logoutMessage((string) parse_url($location, PHP_URL_QUERY));
        static::assertInstanceOf(ReceivedLogoutResponse::class, $received);

        return [$this->validated($received, self::SINGLE_LOGOUT), $received->relayState];
    }

    private function validated(ReceivedLogoutResponse $received, string $location): AcceptedLogoutResponse
    {
        return $received->validate(
            new LogoutResponseValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
            $this->identityProvider(),
            new ServiceProvider(
                self::SERVICE_PROVIDER,
                [],
                [],
                new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, self::ASSERTION_CONSUMER, 0)]),
                [new Endpoint(Binding::HttpRedirect, $location)],
            ),
            $location,
            self::LOGOUT_REQUEST_ID,
        );
    }

    private static function withoutActiveKey(): void
    {
        $keys = self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class);
        $key = $keys->findActive(self::tenant(), new SamlSigning()) ?? static::fail('The tenant holds no active SAML key.');
        $key->startRetiring(self::currentSecond(), self::currentSecond()->modify('+1 day'));
        $keys->save($key);
    }

    private static function withAKeyNotOpenedYet(): void
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

    private function sessionOf(AcceptedAssertion $assertion): AuthenticationSession
    {
        return (
            self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)
                ->find(Uuid::fromString(self::sessionIndex($assertion))) ?? static::fail('The session of the assertion is gone.')
        );
    }

    /**
     * @return array{action: string, fields: array<string, string>}
     */
    private function form(): array
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $form = $this->browser->getCrawler()->filter('form')->first();
        $fields = [];
        $form->filter('input[type="hidden"]')->each(static function (Crawler $input) use (&$fields): void {
            $fields[(string) $input->attr('name')] = (string) $input->attr('value');
        });

        return [
            'action' => (string) $form->attr('action'),
            'fields' => $fields,
        ];
    }

    private function identityProvider(): IdentityProvider
    {
        $this->browser->request('GET', '/saml/metadata');

        return (
            new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
                SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
            )->identityProvider ?? static::fail('The tenant serves no identity provider.')
        );
    }

    /**
     * spec/saml.md section 6.4 step 7
     */
    private static function sessionIndex(AcceptedAssertion $assertion): string
    {
        return $assertion->assertion->authnStatement->sessionIndex ?? static::fail('The assertion carries no SessionIndex.');
    }

    private static function pathOf(string $url): string
    {
        return parse_url($url, PHP_URL_PATH) . '?' . parse_url($url, PHP_URL_QUERY);
    }

    private static function authnRequest(string $id = '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b'): AuthnRequest
    {
        return new AuthnRequest($id, self::currentSecond(), new Issuer(self::SERVICE_PROVIDER), self::SINGLE_SIGN_ON, self::ASSERTION_CONSUMER);
    }

    private static function signing(): Signing
    {
        return new Signing(MetadataFixtures::signingKey('sp'));
    }
}
