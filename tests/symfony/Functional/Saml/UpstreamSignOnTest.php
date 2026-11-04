<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use App\Saml\SamlSigning;
use App\Saml\UpstreamSignOnReferences;
use App\Saml\UpstreamSignOns;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
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
use function count;
use function parse_str;
use function parse_url;
use function strtok;
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
 * beffroi/saml, spec/saml.md S-48 to S-51, section 6.11
 */
final class UpstreamSignOnTest extends ConsoleTestCase
{
    use SignOnFromTheLoginPage;

    private const string SERVICE_PROVIDER = 'test_service_provider';

    private const string SIGN_ON = '/saml/sp/sign-on';

    private const string ADDRESS = 'alice@example.org';

    private const string DRAWN = 'the reference the step of the address drew';

    private const string SINGLE_SIGN_ON = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    /**
     * S-48
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
     * S-48
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
     * S-48
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
     * S-50
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
     * S-50, section 7
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
     * S-49
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
     * S-51, bindings.md section 6.7, SAML Bindings §3.5.5.1
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
     * S-51, Architecture §5.7
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
     * S-51, SAML Bindings §3.4.5.1
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
     * S-48, S-51
     */
    #[Test]
    public function aProviderWhoseDocumentWasNeverAcceptedIsRefused(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();

        // When
        $this->signOnAs($interaction, 'carol@encrypting.example');

        // Then
        $this->assertRefusedAndRemembersNothing();
    }

    /**
     * S-51
     */
    #[Test]
    #[DataProvider('provideReferencesNotDrawnForTheSignOn')]
    public function aSignOnWithoutItsReferenceStartsNothing(?string $reference, string $identityProvider): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeTheAddress($interaction, self::ADDRESS);
        $drawn = $this->presentedReference();

        // When
        $this->browser->request('GET', self::SIGN_ON, [
            'interaction' => $interaction,
            'identity_provider' => $identityProvider,
            ...($reference === null ? [] : ['reference' => $reference === self::DRAWN ? $drawn : $reference]),
        ]);

        // Then
        $this->assertRefusedAndRemembersNothing();
    }

    /**
     * @return iterable<string, array{string|null, string}>
     */
    public static function provideReferencesNotDrawnForTheSignOn(): iterable
    {
        yield 'none' => [null, IdentityProviderDocuments::SIMPLESAMLPHP];
        yield 'another' => ['Ab3xQ0kQ1n0oG2d9V5m8Zr4wY7tL6pHcEeFsUjKiN1o', IdentityProviderDocuments::SIMPLESAMLPHP];
        yield 'drawn for another provider' => [self::DRAWN, IdentityProviderDocuments::SIGNED];
    }

    /**
     * S-51
     */
    #[Test]
    public function theLoginAPageWaitsForStartsNoSignOnWithoutItsReference(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $this->browser->request('GET', '/account');

        // When
        $this->browser->request('GET', self::SIGN_ON, [
            'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        $this->assertRefusedAndRemembersNothing();
    }

    /**
     * S-51
     */
    #[Test]
    public function aReferencePresentedTwiceStartsOneSignOn(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeTheAddress($interaction, self::ADDRESS);
        $signOn = self::string($this->browser->getResponse()->headers->get('Location'));
        $this->browser->followRedirect();

        // When
        $this->browser->request('GET', $signOn);

        // Then
        $response = $this->browser->getResponse();
        $remembered = $this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY);
        static::assertIsArray($remembered);
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'saml_upstream_sign_on_refused', 1],
            [$response->getStatusCode(), $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'), count($remembered)],
        );
    }

    /**
     * S-51, section 7
     */
    #[Test]
    public function aReferenceOlderThanItsLifeStartsNothing(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $interaction = $this->beginAuthorization();
        $this->typeTheAddress($interaction, self::ADDRESS);
        self::mockTime(Clock::get()->now()->modify('+' . (UpstreamSignOnReferences::LIFE + 1) . ' seconds'));

        // When
        $this->browser->followRedirect();

        // Then
        $this->assertRefusedAndRemembersNothing();
    }

    /**
     * S-51, section 6.11 step 5
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
     * S-51
     */
    #[Test]
    public function anUnknownInteractionIsRefused(): void
    {
        // Given
        self::generate();
        self::accept(IdentityProviderDocuments::simpleSamlPhp());
        $this->beginAuthorization();

        // When
        $this->browser->request('GET', self::SIGN_ON, [
            'interaction' => 'an-interaction-nobody-began',
            'identity_provider' => IdentityProviderDocuments::SIMPLESAMLPHP,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('unknown_interaction', $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'));
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

    private function signOn(string $interaction): Crawler
    {
        return $this->signOnAs($interaction, self::ADDRESS);
    }

    private function presentedReference(): string
    {
        $query = [];
        parse_str((string) parse_url(self::string($this->browser->getResponse()->headers->get('Location')), PHP_URL_QUERY), $query);

        return self::string($query['reference'] ?? null);
    }

    private function assertRefusedAndRemembersNothing(): void
    {
        $response = $this->browser->getResponse();
        static::assertSame(
            [Response::HTTP_BAD_REQUEST, 'saml_upstream_sign_on_refused', null, null],
            [
                $response->getStatusCode(),
                $this->browser->getCrawler()->filter('[data-error]')->attr('data-error'),
                $response->headers->get('Location'),
                $this->readHttpSession()->get(UpstreamSignOns::SESSION_KEY),
            ],
            self::string($response->getContent()),
        );
    }

    private static function generate(): void
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
    }

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
        // The action carries the address of S-68 in its query, the message in the body.
        static::assertSame(self::SINGLE_SIGN_ON, strtok((string) $form->attr('action'), '?'));
        $fields = [];
        $form->filter('input[type="hidden"]')->each(static function (Crawler $input) use (&$fields): void {
            $fields[(string) $input->attr('name')] = (string) $input->attr('value');
        });

        return new PostReceiver(SamlLoader::create())->authnRequest($fields);
    }

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
