<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Group\Group;
use Beffroi\Core\Domain\Group\GroupSource;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\GroupRepositoryInterface;
use Beffroi\Core\Port\GroupsOfAPersonInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml\Tests\Fixture\UpstreamResponses;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use Beffroi\Xml\Dsig\PrivateKey;
use DateTimeImmutable;
use function array_map;
use function http_build_query;
use function parse_url;
use function str_starts_with;
use function ucfirst;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md S-52 to S-59, section 6.14, the acceptance of issue #784: in a deployment whose tenant is
 * a service provider (tests/symfony/config/config_test_service_provider.yml), the SimpleSAMLphp identity provider of
 * the judge declared and its document accepted, an interaction sent to it is answered by a response signed by its key,
 * posted to the assertion consumer service, which signs the person in and resumes the interaction; what the response
 * does not answer is refused, and nobody is signed in.
 */
final class AssertionConsumerServiceTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = 'test_service_provider';

    private const string ASSERTION_CONSUMER_SERVICE = 'https://op.test/saml/sp/acs';

    private const string AUDIENCE = 'https://op.test/saml/sp/metadata';

    private const string SINGLE_SIGN_ON = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService';

    private const string ADDRESS = 'alice@example.org';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    /**
     * The acceptance of issue #784, S-53, S-59: a signed response for the request of the interaction completes the
     * interaction with a code for the client.
     */
    #[Test]
    public function aSignedResponseCompletesTheInteractionWithACode(): void
    {
        // Given
        self::provisioned();
        $interaction = $this->beginAuthorization();
        $request = $this->signOn($interaction);

        // When
        $this->post($this->response($request));

        // Then
        static::assertArrayHasKey('code', self::redirectedQuery($this->resumed()));
    }

    /**
     * The acceptance of issue #784, S-56, issues #781 and #782: the first sign-in creates the person the provider names,
     * its address verified, and makes it a member of the group the declaration maps its value to.
     */
    #[Test]
    public function theFirstSignInCreatesThePersonWithItsGroup(): void
    {
        // Given
        self::provisioned();
        $members = new Group(Uuid::v7(), self::tenant(), 'Members', GroupSource::Local, self::currentSecond());
        self::service('test.beffroi.groups', GroupRepositoryInterface::class)->save($members);
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, ['eduPersonAffiliation' => ['member', 'student']]));

        // Then
        $alice = self::person();
        static::assertSame([self::ADDRESS, true, ['Members']], [
            $alice->username,
            $alice->emailVerified,
            array_map(
                static fn ($membership): string => $membership->group->name,
                self::service('test.beffroi.groups_of_a_person', GroupsOfAPersonInterface::class)->of($alice),
            ),
        ]);
    }

    /**
     * The acceptance of issue #784, S-55: the client gets the same subject at every sign-in of that person, the person
     * found again by its linked identity.
     */
    #[Test]
    public function theClientGetsTheSameSubAtEverySignIn(): void
    {
        // Given
        self::provisioned();
        $this->post($this->response($this->signOn($this->beginAuthorization())));
        $first = $this->idToken($this->resumed());
        $this->browser->getCookieJar()->clear();
        $this->post($this->response($this->signOn($this->beginAuthorization())));

        // When
        $second = $this->idToken($this->resumed());

        // Then
        static::assertSame($first['sub'], $second['sub']);
    }

    /**
     * S-57, OIDC Core §2: the AuthnInstant of the assertion is the auth_time the client reads, and the methods are a
     * federated assertion and the password its class names.
     */
    #[Test]
    public function theAuthnInstantIsTheAuthTimeOfTheSession(): void
    {
        // Given
        self::provisioned();
        $authnInstant = new DateTimeImmutable('@' . (Clock::get()->now()->getTimestamp() - 30));
        $this->post($this->response($this->signOn($this->beginAuthorization()), authnInstant: $authnInstant));

        // When
        $claims = $this->idToken($this->resumed());

        // Then
        static::assertSame([$authnInstant->getTimestamp(), ['fed', 'pwd']], [$claims['auth_time'], $claims['amr']]);
    }

    /**
     * The acceptance of issue #784, S-53, M-8, Core §2.5.1.4: a response for another audience signs nobody in.
     */
    #[Test]
    public function aResponseForAnotherAudienceIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, audience: 'https://another.example/saml/sp/metadata'));

        // Then
        $this->assertRefused('An AudienceRestriction does not hold our entity ID among its audiences (M-8).');
    }

    /**
     * The acceptance of issue #784, S-53, M-10: a response to a request nobody sent signs nobody in.
     */
    #[Test]
    public function aResponseToARequestNobodySentIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response([...$request, 'id' => '_ffffffffffffffffffffffffffffffffffffffff']));

        // Then
        $this->assertRefused('The InResponseTo of the response is not the one the consumer expects (M-10).');
    }

    /**
     * The acceptance of issue #784, S-53: a form posted a second time finds nothing the browser remembers, its request
     * forgotten at the first post, and signs nobody in again.
     */
    #[Test]
    public function aResponsePostedTwiceIsRefused(): void
    {
        // Given
        self::provisioned();
        $form = $this->response($this->signOn($this->beginAuthorization()));
        $this->post($form);
        self::forgetEvents();

        // When
        $this->post($form);

        // Then
        $this->assertRefused('The response answers no request this browser remembers (spec/saml.md S-53).');
    }

    /**
     * The acceptance of issue #784, S-53, M-11: the assertion of a response accepted, presented again under a request
     * this browser does remember, is refused by the replay store.
     */
    #[Test]
    public function anAssertionPresentedAgainIsRefusedByTheReplayStore(): void
    {
        // Given
        self::provisioned();
        $this->post($this->response($this->signOn($this->beginAuthorization()), assertionId: '_assertion-of-alice'));
        $this->browser->getCookieJar()->clear();
        self::forgetEvents();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, assertionId: '_assertion-of-alice'));

        // Then
        $this->assertRefused('The assertion was already accepted from its issuer (M-11).');
    }

    /**
     * The acceptance of issue #784, S-53, decision 0029: an unsolicited response, which answers no request and carries
     * no RelayState, signs nobody in.
     */
    #[Test]
    public function anUnsolicitedResponseIsRefused(): void
    {
        // Given
        self::provisioned();
        $this->signOn($this->beginAuthorization());

        // When
        $this->post(UpstreamResponses::form(
            UpstreamResponses::simpleSamlPhpKey(),
            IdentityProviderDocuments::SIMPLESAMLPHP,
            self::ASSERTION_CONSUMER_SERVICE,
            self::AUDIENCE,
            null,
            Clock::get()->now(),
            ['mail' => [self::ADDRESS]],
        ));

        // Then
        $this->assertRefused('The response answers no request this browser remembers (spec/saml.md S-53).');
    }

    /**
     * The acceptance of issue #784, S-53, M-3: a response signed by a key the metadata of the provider do not publish
     * signs nobody in, whatever key the message names.
     */
    #[Test]
    public function aSignatureUnderAKeyOutsideTheMetadataIsRefused(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization());

        // When
        $this->post($this->response($request, key: MetadataFixtures::signingKey('idp')));

        // Then
        $this->assertRefused('No trusted key verifies the signature over SignedInfo (D-7, D-8).');
    }

    /**
     * S-39, S-52: the assertion consumer service the metadata of the service provider announce is the URL the router
     * generates for its route.
     */
    #[Test]
    public function theMetadataAnnounceTheUrlOfTheRoute(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', '/saml/sp/metadata');

        // Then
        $serviceProvider = new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
            SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
        )->serviceProvider ?? static::fail('The tenant serves no service provider.');
        static::assertSame(
            self::tenant()->issuer->origin()
                . self::service('router', UrlGeneratorInterface::class)->generate(ServiceProviderRoutes::ASSERTION_CONSUMER_SERVICE),
            $serviceProvider->assertionConsumerServices->default()->location,
        );
    }

    /**
     * S-52, S-28: the response the provider posts from its own site, which comes without the session cookie, is posted
     * again from the origin of the provider, and that post signs the person in.
     */
    #[Test]
    public function aResponsePostedFromAnotherSiteIsPostedAgainAndSignsThePersonIn(): void
    {
        // Given
        self::provisioned();
        $form = $this->response($this->signOn($this->beginAuthorization()));
        $this->postedFromAnotherSite('/saml/sp/acs', http_build_query($form));

        // When
        $this->postedAgain();

        // Then
        static::assertArrayHasKey('code', self::redirectedQuery($this->resumed()));
    }

    /**
     * S-58, S-49, OIDC Core §3.1.2.1: an AuthnInstant older than the max_age of the client opens no session, and the
     * request is sent once more, with ForceAuthn.
     */
    #[Test]
    public function anAssertionOlderThanTheMaxAgeSendsTheRequestOnceMoreWithForceAuthn(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization(['max_age' => '60']));

        // When
        $this->post($this->response($request, authnInstant: Clock::get()->now()->modify('-2 hours')));

        // Then
        static::assertSame([true, []], [$this->sentRequest()->forceAuthn, self::events(UserAuthenticated::class)]);
    }

    /**
     * S-58, OIDC Core §3.1.2.6: an assertion that answers the request sent with ForceAuthn still older than the max_age
     * is answered with login_required at the redirection URI of the client, and nothing is sent a third time.
     */
    #[Test]
    public function anAssertionStillOlderThanTheMaxAgeIsAnsweredLoginRequired(): void
    {
        // Given
        self::provisioned();
        $this->post($this->response($this->signOn($this->beginAuthorization(['max_age' => '60'])), authnInstant: Clock::get()->now()->modify('-2 hours')));
        $again = $this->sentRequestOfTheAnswer();

        // When
        $this->post($this->response($again, authnInstant: Clock::get()->now()->modify('-2 hours')));

        // Then
        static::assertSame('login_required', self::redirectedQuery($this->browser->getResponse())['error'] ?? null);
    }

    /**
     * S-58, S-49: a client that asked for prompt=login sends ForceAuthn from the first request, and an AuthnInstant
     * before the interaction began is answered with login_required, never sent round again.
     */
    #[Test]
    public function anAssertionOlderThanAPromptLoginIsAnsweredLoginRequired(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOn($this->beginAuthorization(['prompt' => 'login']));

        // When
        $this->post($this->response($request, authnInstant: Clock::get()->now()->modify('-5 seconds')));

        // Then
        static::assertSame('login_required', self::redirectedQuery($this->browser->getResponse())['error'] ?? null);
    }

    /**
     * S-59: the login a page of the provider waits for comes back to that page, its route and its parameters as the
     * provider remembered them.
     */
    #[Test]
    public function theLoginAPageWaitsForComesBackToThatPage(): void
    {
        // Given
        self::provisioned();
        $request = $this->signOnFromTheAccount();

        // When
        $this->post($this->response($request));

        // Then
        static::assertSame('/account', $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * S-49, S-58, OIDC Core §3.1.2.1: a client that names bob by an id_token_hint while alice is signed in has the
     * request force a login at the provider, whose own session would answer for alice.
     */
    #[Test]
    public function anIdTokenHintNamingAnotherPersonForcesTheLogin(): void
    {
        // Given
        self::provisioned();
        $bob = $this->idTokenOf('bob');
        $this->browser->getCookieJar()->clear();
        $this->idTokenOf('alice');
        $interaction = $this->beginAuthorization(['id_token_hint' => $bob]);

        // When
        $this->browser->request('GET', '/saml/sp/sign-on', [
            'interaction' => $interaction,
            'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        static::assertTrue($this->sentRequest()->forceAuthn);
    }

    /**
     * S-58, OIDC Core §3.1.2.6: the provider asserting alice again for a client that names bob, ForceAuthn
     * notwithstanding, is answered with login_required, and never sent round again.
     */
    #[Test]
    public function aProviderThatAssertsAnotherPersonThanTheHintIsAnsweredLoginRequired(): void
    {
        // Given
        self::provisioned();
        $bob = $this->idTokenOf('bob');
        $this->browser->getCookieJar()->clear();
        $this->idTokenOf('alice');
        $request = $this->signOn($this->beginAuthorization(['id_token_hint' => $bob]));

        // When
        $this->post($this->response($request));

        // Then
        static::assertSame('login_required', self::redirectedQuery($this->browser->getResponse())['error'] ?? null);
    }

    /**
     * S-59: a page that asks a person signed in for a login sends a request that forces one, and an AuthnInstant
     * before that request was issued, a provider that did not authenticate the person again, is refused and sent
     * nowhere again.
     */
    #[Test]
    public function aPageIsRefusedAnAuthenticationOlderThanItsRequest(): void
    {
        // Given
        self::provisioned();
        $this->idTokenOf('alice');
        $this->httpSession(static function (SessionInterface $httpSession): void {
            $httpSession->set(LoginTarget::SESSION_KEY, [
                'route' => 'beffroi_interaction_account',
                'parameters' => [],
                'step_up' => null,
            ]);
        });
        $this->browser->request('GET', '/saml/sp/sign-on', [
            'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);
        $request = $this->sentRequestOfTheAnswer();
        self::forgetEvents();

        // When
        $this->post($this->response($request, authnInstant: Clock::get()->now()->modify('-1 hour')));

        // Then
        $this->assertRefused('The identity provider did not authenticate the person again, ForceAuthn notwithstanding (spec/saml.md S-59).');
    }

    /**
     * The tenant holds a SAML key, a key that signs its ID tokens, and the document of the provider of the judge.
     */
    private static function provisioned(): void
    {
        self::generate();
        self::signingKey();
        self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedUpstreamMetadata(
                Uuid::v7(),
                self::tenant(),
                IdentityProviderDocuments::SIMPLESAMLPHP,
                IdentityProviderDocuments::simpleSamlPhp(),
                null,
                self::currentSecond(),
            ));
    }

    private static function generate(): void
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

    /**
     * @param array<string, string> $parameters
     */
    private function beginAuthorization(array $parameters = []): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', $parameters));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));

        return self::redirectedInteraction($response);
    }

    /**
     * The request the sign-on of the interaction sent the provider, as the provider reads it.
     *
     * @return array{id: string, relay_state: string}
     */
    private function signOn(string $interaction): array
    {
        $this->browser->request('GET', '/saml/sp/sign-on', [
            'interaction' => $interaction,
            'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        return $this->sentRequestOfTheAnswer();
    }

    /**
     * The login the home of the account waits for sent to the provider, its address typed as a person types it.
     *
     * @return array{id: string, relay_state: string}
     */
    private function signOnFromTheAccount(): array
    {
        $this->browser->request('GET', '/account');
        $this->browser->request('GET', '/saml/sp/sign-on', [
            'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        return $this->sentRequestOfTheAnswer();
    }

    /**
     * The ID and the RelayState of the request the last answer carries to the provider.
     *
     * @return array{id: string, relay_state: string}
     */
    private function sentRequestOfTheAnswer(): array
    {
        $location = self::string($this->browser->getResponse()->headers->get('Location'));
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest((string) parse_url($location, PHP_URL_QUERY));
        $request = $this->sentRequest();

        return [
            'id' => $request->id,
            'relay_state' => $received->relayState ?? static::fail('The request carries no RelayState.'),
        ];
    }

    /**
     * The request the last answer carries to the provider, validated on its side under the metadata the service
     * provider serves.
     */
    private function sentRequest(): AuthnRequest
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $location = self::string($response->headers->get('Location'));
        static::assertStringStartsWith(self::SINGLE_SIGN_ON . '?', $location);
        $received = new RedirectReceiver(SamlLoader::create())->authnRequest((string) parse_url($location, PHP_URL_QUERY));
        $this->browser->request('GET', '/saml/sp/metadata');
        $serviceProvider = new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
            SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
        )->serviceProvider ?? static::fail('The tenant serves no service provider.');
        $identityProvider = new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
            SamlLoader::create()->load(IdentityProviderDocuments::simpleSamlPhp()),
        )->identityProvider ?? static::fail('The document holds no identity provider.');

        return $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), Clock::get()),
            $serviceProvider,
            $identityProvider,
            self::SINGLE_SIGN_ON,
        )->request;
    }

    /**
     * The form the provider posts for the request, signed by its key.
     *
     * @param array{id: string, relay_state: string} $request
     * @param array<string, list<string>> $attributes
     *
     * @return array<string, string>
     */
    private function response(
        array $request,
        array $attributes = [],
        string $audience = self::AUDIENCE,
        ?DateTimeImmutable $authnInstant = null,
        ?string $assertionId = null,
        ?PrivateKey $key = null,
        string $person = 'alice',
    ): array {
        return UpstreamResponses::form(
            $key ?? UpstreamResponses::simpleSamlPhpKey(),
            IdentityProviderDocuments::SIMPLESAMLPHP,
            self::ASSERTION_CONSUMER_SERVICE,
            $audience,
            $request['id'],
            Clock::get()->now(),
            ['mail' => [$person . '@example.org'], 'givenName' => [ucfirst($person)], ...$attributes],
            $request['relay_state'],
            $authnInstant,
            new NameId('persistent-' . $person, NameIdFormat::Persistent),
            assertionId: $assertionId,
        );
    }

    /**
     * @param array<string, string> $form
     */
    private function post(array $form): void
    {
        $this->browser->request('POST', '/saml/sp/acs', $form);
    }

    /**
     * The answer of the client once the browser is sent back to the interaction, past a consent the client asks for.
     */
    private function resumed(): Response
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        $this->browser->followRedirect();
        $location = self::string($this->browser->getResponse()->headers->get('Location'));
        if (str_starts_with($location, '/consent?')) {
            $this->browser->submit($this->browser->followRedirect()->selectButton('Allow')->form());
        }

        return $this->browser->getResponse();
    }

    /**
     * A sign-in of that person through the provider, from an interaction to the ID token its code is exchanged for.
     */
    private function idTokenOf(string $person): string
    {
        $this->post($this->response($this->signOn($this->beginAuthorization()), person: $person));
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => self::redirectedQuery($this->resumed())['code'] ?? static::fail('The client got no code.'),
            'redirect_uri' => 'http://127.0.0.1/callback',
            'code_verifier' => self::CODE_VERIFIER,
            'client_id' => 'native-app',
        ]);

        return self::string(self::json($this->browser->getResponse())['id_token'] ?? null);
    }

    /**
     * The claims of the ID token the code of the answer is exchanged for.
     *
     * @return array<string, mixed>
     */
    private function idToken(Response $answer): array
    {
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => self::redirectedQuery($answer)['code'] ?? static::fail('The client got no code.'),
            'redirect_uri' => 'http://127.0.0.1/callback',
            'code_verifier' => self::CODE_VERIFIER,
            'client_id' => 'native-app',
        ]);

        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token'] ?? null));
    }

    /**
     * Refused with the page of a refusal, for the rule given, and nobody signed in.
     */
    private function assertRefused(string $rule): void
    {
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'saml_assertion_refused', 'saml_assertion_refused: ' . $rule, []],
            [
                $response->getStatusCode(),
                $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'),
                $this->browser->getCrawler()->filter('[data-description]')->text(),
                self::events(UserAuthenticated::class),
            ],
            self::string($response->getContent()),
        );
    }

    private static function person(): User
    {
        $people = self::service('test.beffroi.users', UserRepositoryInterface::class)->findAllByEmail(self::tenant(), new EmailAddress(self::ADDRESS));
        static::assertCount(1, $people);

        return $people[0];
    }
}
