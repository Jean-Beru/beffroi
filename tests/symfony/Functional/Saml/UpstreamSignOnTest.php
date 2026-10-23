<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Saml\UpstreamSignOns;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\ReceivedAuthnRequest;
use Beffroi\Saml2\Bindings\RedirectReceiver;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Validation\AcceptedAuthnRequest;
use Beffroi\Saml2\Model\Validation\Authentication;
use Beffroi\Saml2\Model\Validation\AuthnRequestValidator;
use DateTimeImmutable;
use function parse_url;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md S-48 to S-51, section 6.11, the acceptance of issue #783: in a deployment whose tenant is
 * a service provider (tests/symfony/config/config_test_service_provider.yml), the SimpleSAMLphp identity provider of
 * the judge declared and its document accepted, an interaction begun at the authorization endpoint is sent to that
 * provider with an AuthnRequest signed by the SAML key of the tenant, which saml2-model's validator accepts on the side
 * of the provider under the metadata the service provider serves, in each binding.
 */
final class UpstreamSignOnTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = 'test_service_provider';

    private const string SIGN_ON = '/saml/sp/sign-on';

    private const string SINGLE_SIGN_ON = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    /**
     * The acceptance of issue #783, S-48: over HTTP-Redirect, the binding of the single sign-on service of the
     * document, the interaction is answered with a redirection to that service, whose request the provider accepts
     * signed over its query string.
     */
    #[Test]
    public function overHttpRedirectTheProviderAcceptsTheRequestSignedOverItsQueryString(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        static::assertSame(Authentication::Binding, $this->acceptedRequest()->authentication);
    }

    /**
     * The acceptance of issue #783, S-48: the document listing its single sign-on service on HTTP-POST alone, the
     * interaction is answered with the page whose form posts to that service a request the provider accepts signed in
     * its XML.
     */
    #[Test]
    public function overHttpPostTheProviderAcceptsTheRequestSignedInItsXml(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        static::assertSame(Authentication::XmlSignature, $this->acceptedRequest(Binding::HttpPost)->authentication);
    }

    /**
     * S-48: the request is issued by the service provider of the tenant, to the single sign-on service of the
     * document, and asks for the response at the assertion consumer service its metadata announce, over HTTP-POST,
     * with a persistent identifier the provider may create.
     */
    #[Test]
    public function theRequestIsTheOneOfTheServiceProviderOfTheTenant(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->signOn($interaction);

        // When
        $request = $this->acceptedRequest()->request;

        // Then
        static::assertEquals(
            [
                new Issuer('https://op.test/saml/sp/metadata'),
                self::SINGLE_SIGN_ON,
                'https://op.test/saml/sp/acs',
                Binding::HttpPost->value,
                new NameIdPolicy(NameIdFormat::Persistent->value, null, true),
            ],
            [
                $request->issuer,
                $request->destination,
                $request->assertionConsumerServiceUrl,
                $request->protocolBinding,
                $request->nameIdPolicy,
            ],
        );
    }

    /**
     * The acceptance of issue #783, S-50: the RelayState is a reference of 43 characters of base64url, the one key of
     * what the HTTP session of the browser remembers, under which are the ID of the request, the provider it was sent
     * to, whether it carried ForceAuthn and the instant it was issued, the interaction it serves and the tenant, and
     * nothing else.
     */
    #[Test]
    public function theRelayStateNamesTheRememberedRequestAndNothingElse(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->signOn($interaction);
        $relayState = $this->received()->relayState ?? static::fail('The request carries no RelayState.');
        $request = $this->acceptedRequest()->request;

        // When
        $remembered = $this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY);

        // Then
        static::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $relayState);
        static::assertSame(
            [
                $relayState => [
                    'tenant' => self::tenant()->id->toRfc4122(),
                    'interaction' => $interaction,
                    'request' => $request->id,
                    'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
                    'force_authn' => false,
                    'issued_at' => $request->issueInstant->getTimestamp(),
                ],
            ],
            $remembered,
        );
    }

    /**
     * S-50, section 7: a browser remembers eight requests at most, the oldest forgotten first.
     */
    #[Test]
    public function aBrowserRemembersEightRequestsAtMost(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->signOn($interaction);
        $first = $this->received()->relayState;

        // When
        for ($signOn = 0; $signOn < UpstreamSignOns::MAX_KEPT; ++$signOn) {
            $this->signOn($interaction);
        }

        // Then
        $remembered = $this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY);
        static::assertIsArray($remembered);
        static::assertCount(UpstreamSignOns::MAX_KEPT, $remembered);
        static::assertArrayNotHasKey((string) $first, $remembered);
    }

    /**
     * The acceptance of issue #783, S-49: an authorization request that asks for a fresh login, by prompt=login or by a
     * max_age the session of the browser exceeds, sets ForceAuthn; one that asks for neither does not.
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideFreshLogins')]
    public function aFreshLoginTheClientAsksForSetsForceAuthn(array $parameters, bool $signedIn, bool $forceAuthn): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        if ($signedIn) {
            $this->signIn(self::user('alice'), new DateTimeImmutable('-1 hour'));
        }
        $interaction = $this->beginAuthorization($parameters);

        // When
        $this->signOn($interaction);

        // Then
        static::assertSame($forceAuthn, $this->acceptedRequest()->request->forceAuthn);
    }

    /**
     * @return iterable<string, array{array<string, string>, bool, bool}>
     */
    public static function provideFreshLogins(): iterable
    {
        yield 'prompt=login' => [['prompt' => 'login'], false, true];
        yield 'a max_age the session exceeds' => [['max_age' => '60'], true, true];
        yield 'a max_age and no session' => [['max_age' => '60'], false, false];
        yield 'neither' => [[], false, false];
    }

    /**
     * S-51, bindings.md section 6.7, SAML Bindings §3.5.5.1: the page that posts the request names its one script by
     * its hash, loads nothing, is framed by nothing, names no "form-action", the single sign-on service sending the
     * browser on to its login page, and is never cached.
     */
    #[Test]
    public function thePageCarriesItsPolicyAndTheCachingOfTheBinding(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [
                "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; base-uri 'none'; frame-ancestors 'none'",
                true,
                true,
                'no-cache',
            ],
            [
                $response->headers->get('Content-Security-Policy'),
                $response->headers->hasCacheControlDirective('no-store'),
                $response->headers->hasCacheControlDirective('no-cache'),
                $response->headers->get('Pragma'),
            ],
        );
    }

    /**
     * S-51, architecture §5.7: the page says the browser goes to the sign-in of its organisation, and not back to an
     * application.
     */
    #[Test]
    public function thePageSaysWhereTheBrowserGoes(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost());
        $interaction = $this->beginAuthorization();

        // When
        $crawler = $this->signOn($interaction);

        // Then
        static::assertSame('Signing in with your organisation', $crawler->filter('title')->text());
    }

    /**
     * S-51, SAML Bindings §3.4.5.1: the redirection is never cached.
     */
    #[Test]
    public function theRedirectionCarriesTheCachingOfTheBinding(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_FOUND, true, true, 'no-cache'],
            [
                $response->getStatusCode(),
                $response->headers->hasCacheControlDirective('no-store'),
                $response->headers->hasCacheControlDirective('no-cache'),
                $response->headers->get('Pragma'),
            ],
        );
    }

    /**
     * The acceptance of issue #783, S-51: a provider the tenant does not declare is the page of a refusal, and the
     * browser is sent nowhere.
     */
    #[Test]
    public function aProviderTheTenantDoesNotDeclareIsRefused(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction, 'https://idp.nobody.example/saml');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('saml_upstream_sign_on_refused', $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'));
        static::assertNull($this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY));
    }

    /**
     * S-51, section 6.11 step 5: a tenant that holds no SAML key signs no request, and serves no service provider.
     */
    #[Test]
    public function aTenantWithoutASamlKeyStartsNoSignOn(): void
    {
        // Given
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOn($interaction);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * The acceptance of issue #783, S-51: an interaction this browser did not begin is the page of an unknown
     * interaction.
     */
    #[Test]
    public function anUnknownInteractionIsRefused(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $this->beginAuthorization();

        // When
        $this->signOn('an-interaction-nobody-began');

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('unknown_interaction', $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'));
    }

    /**
     * An interaction begun at the authorization endpoint, which sends the browser to the login.
     *
     * @param array<string, string> $parameters
     */
    private function beginAuthorization(array $parameters = []): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', $parameters));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));

        return self::redirectedInteraction($response);
    }

    private function signOn(string $interaction, string $identityProvider = IdentityProviderDocuments::SIMPLESAMLPHP): Crawler
    {
        return $this->browser->request('GET', self::SIGN_ON, [
            'interaction' => $interaction,
            'identity_provider' => $identityProvider,
        ]);
    }

    /**
     * The SAML key of the tenant, drawn as an operator draws it.
     */
    private static function generate(): void
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

    /**
     * The document of the identity provider of the judge accepted for the tenant.
     */
    private static function accept(string $document): void
    {
        self::service('test.beffroi.saml_upstream_accepted_metadata', AcceptedMetadataRepositoryInterface::class)
            ->save(new AcceptedUpstreamMetadata(
                Uuid::v7(),
                self::tenant(),
                IdentityProviderDocuments::SIMPLESAMLPHP,
                $document,
                null,
                self::currentSecond(),
            ));
    }

    /**
     * The request the answer carries to the provider, received as the provider receives it: from the query string of
     * the redirection, or from the form of the page.
     */
    private function received(): ReceivedAuthnRequest
    {
        $response = $this->browser->getResponse();
        if ($response->isRedirection()) {
            $location = $response->headers->get('Location') ?? static::fail('The redirection names no location.');
            static::assertStringStartsWith(self::SINGLE_SIGN_ON . '?', $location);

            return new RedirectReceiver(SamlLoader::create())->authnRequest((string) parse_url($location, PHP_URL_QUERY));
        }
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $form = $this->browser->getCrawler()->filter('form')->first();
        static::assertSame(self::SINGLE_SIGN_ON, $form->attr('action'));
        $fields = [];
        $form->filter('input[type="hidden"]')->each(static function (Crawler $input) use (&$fields): void {
            $fields[(string) $input->attr('name')] = (string) $input->attr('value');
        });

        return new PostReceiver(SamlLoader::create())->authnRequest($fields);
    }

    /**
     * The request as the provider validates it, at its single sign-on service, under the certificate the metadata of
     * the service provider of the tenant publish.
     */
    private function acceptedRequest(Binding $binding = Binding::HttpRedirect): AcceptedAuthnRequest
    {
        $received = $this->received();

        return $received->validate(
            new AuthnRequestValidator(SamlLoader::create(), Clock::get()),
            $this->serviceProvider(),
            $this->identityProvider($binding),
            self::SINGLE_SIGN_ON,
        );
    }

    private function serviceProvider(): ServiceProvider
    {
        $this->browser->request('GET', '/saml/sp/metadata');

        return (
            new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
                SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
            )->serviceProvider ?? static::fail('The tenant serves no service provider.')
        );
    }

    private function identityProvider(Binding $binding): IdentityProvider
    {
        $document = $binding === Binding::HttpPost ? IdentityProviderDocuments::simpleSamlPhpSigningOnOverPost() : IdentityProviderDocuments::simpleSamlPhp();

        return (
            new MetadataReader(
                SamlLoader::create(),
                new MockClock(),
            )->readTrusted(SamlLoader::create()->load($document))->identityProvider ?? static::fail('The document holds no identity provider.')
        );
    }
}
