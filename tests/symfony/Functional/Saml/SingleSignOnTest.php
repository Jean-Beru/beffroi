<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Saml;

use Beffroi\Bundle\Saml\SamlSigning;
use Beffroi\Bundle\Tests\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Writing\Signing;
use function array_combine;
use function array_map;
use function parse_url;
use const PHP_URL_PATH;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md section 6.4, the acceptance of issue #731: the service provider https://sp.example.org/saml
 * of the configuration of the test, its metadata accepted and its requests signed with the test key of a service
 * provider of saml2-model, sends a request in each binding, and the browser posts back a response that saml2-model's
 * validator accepts under the certificate the metadata of the tenant publish.
 */
final class SingleSignOnTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = ServiceProviderDocuments::SIGNED;

    private const string ASSERTION_CONSUMER = ServiceProviderDocuments::SIGNED . '/acs';

    private const string SINGLE_SIGN_ON = 'https://op.test/saml/sso';

    private const string PASSWORD = 'correct horse battery staple';

    private User $alice;

    protected function setUp(): void
    {
        parent::setUp();
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        self::service('test.beffroi.saml_accepted_metadata', AcceptedMetadataRepositoryInterface::class)->save(new AcceptedMetadata(
            Uuid::v7(),
            self::tenant(),
            self::SERVICE_PROVIDER,
            ServiceProviderDocuments::exampleOrg(),
            null,
            self::currentSecond(),
        ));
        $this->alice = self::userWithPassword('alice', self::PASSWORD);
        $this->alice->changeEmail(new EmailAddress('alice@example.com'), true, self::currentSecond());
        $this->alice->updateProfile(new Profile(name: 'Alice Liddell'), self::currentSecond());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($this->alice);
    }

    /**
     * The acceptance of issue #731, section 6.4, B-2: a request signed over HTTP-Redirect from a browser signed in is
     * answered with the page whose form posts a response the model's validator accepts, both signed (S-15).
     */
    #[Test]
    public function aRequestOverHttpRedirectIsAnsweredWithASignedAssertion(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->redirected('state-1');

        // Then
        static::assertSame(SignatureCoverage::AssertionAndResponse, $this->accepted()->coverage);
    }

    /**
     * The acceptance of issue #731, section 6.4, M-2: a request signed in its XML over HTTP-POST is answered the same
     * way.
     */
    #[Test]
    public function aRequestOverHttpPostIsAnsweredWithASignedAssertion(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->posted('state-1');

        // Then
        static::assertSame(SignatureCoverage::AssertionAndResponse, $this->accepted()->coverage);
    }

    /**
     * The acceptance of issue #731, B-9, section 6.8: the RelayState a request carried comes back byte for byte.
     */
    #[Test]
    public function theRelayStateComesBackByteForByte(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->posted("a state <with> \"quotes\", & spaces, \u{e9}");

        // Then
        static::assertSame("a state <with> \"quotes\", & spaces, \u{e9}", $this->form()['fields']['RelayState'] ?? null);
    }

    /**
     * S-14, S-16: the assertion names the service provider, the endpoint of its metadata and the request, and carries
     * the attributes its declaration maps from the claims of the user.
     */
    #[Test]
    public function theAssertionIsAddressedToTheRequestAndCarriesTheMappedClaims(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->redirected('state-1');

        // Then
        $assertion = $this->accepted()->assertion;
        static::assertSame(
            [
                'https://op.test/saml/metadata',
                [[self::SERVICE_PROVIDER]],
                self::ASSERTION_CONSUMER,
                ['urn:oid:0.9.2342.19200300.100.1.3' => ['alice@example.com'], 'urn:oid:2.16.840.1.113730.3.1.241' => ['Alice Liddell']],
            ],
            [
                $assertion->issuer->entityId,
                $assertion->conditions->audiences,
                $assertion->confirmation->recipient,
                array_combine(
                    array_map(static fn ($attribute): string => $attribute->name, $assertion->attributes),
                    array_map(static fn ($attribute): array => $attribute->values, $assertion->attributes),
                ),
            ],
        );
    }

    /**
     * S-17: a browser without a session goes to the login of the provider, which every page of the provider that is
     * not an authorization request signs in through.
     */
    #[Test]
    public function aBrowserWithoutASessionGoesToTheLogin(): void
    {
        // When
        $this->redirected('state-1');

        // Then
        static::assertTrue($this->browser->getResponse()->isRedirect('/login'), (string) $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * S-17, S-18: once signed in on the form, the browser comes back to the request that waited for it, which is
     * answered.
     */
    #[Test]
    public function aBrowserThatSignsInIsAnswered(): void
    {
        // Given
        $this->posted('state-1');

        // When
        $this->logIn();

        // Then
        static::assertSame('state-1', $this->form()['fields']['RelayState'] ?? null);
    }

    /**
     * The acceptance of issue #731, S-17: a user signed in through the authorization endpoint of OpenID Connect is not
     * asked to sign in again, the SAML user and the OpenID Connect user being one user of the core.
     */
    #[Test]
    public function aUserSignedInByOpenIdConnectIsNotAskedAgain(): void
    {
        // Given
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $this->browser->followRedirect();
        $this->submitLogin();

        // When
        $this->redirected('state-1');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * The acceptance of issue #731, S-13: the same NameID at every login to the same service provider.
     */
    #[Test]
    public function theSameNameIdComesAtEveryLogin(): void
    {
        // Given
        $this->signIn($this->alice);
        $this->redirected('state-1');
        $first = $this->accepted()->assertion->nameId;
        $this->signIn($this->alice);

        // When
        $this->redirected('state-2');

        // Then
        static::assertEquals($first, $this->accepted()->assertion->nameId);
    }

    /**
     * S-13: the NameID is persistent, qualified by both entities, and is not the "sub".
     */
    #[Test]
    public function theNameIdIsPersistentAndNotTheSubject(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->redirected('state-1');

        // Then
        $nameId = $this->accepted()->assertion->nameId;
        static::assertSame(
            ['urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', 'https://op.test/saml/metadata', self::SERVICE_PROVIDER, false],
            [$nameId->format->value, $nameId->nameQualifier, $nameId->spNameQualifier, $nameId->value === $this->alice->subject->value],
        );
    }

    /**
     * Section 6.8, bindings.md section 6.7, SAML Bindings §3.5.5.1: the page names its one script by its hash, posts
     * to the origin of the assertion consumer service and nowhere else, and is never cached.
     */
    #[Test]
    public function thePageCarriesItsPolicyAndTheCachingOfTheBinding(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->redirected('state-1');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            [
                "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; form-action https://sp.example.org; base-uri 'none'; frame-ancestors 'none'",
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
     * Section 6.8: a body that is not a form is refused before the package reads it.
     */
    #[Test]
    public function aBodyThatIsNotAFormIsRefused(): void
    {
        // When
        $this->browser->request('POST', '/saml/sso', [], [], ['CONTENT_TYPE' => 'application/json'], '{"SAMLRequest":"x"}');

        // Then
        static::assertSame(Response::HTTP_UNSUPPORTED_MEDIA_TYPE, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Section 6.3, S-9: an unsigned request of a provider that signs gets the page of a refusal and no SAML answer.
     */
    #[Test]
    public function anUnsignedRequestIsRefusedWithoutSamlAnswer(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->browser->request('GET', self::pathOf(new RedirectSender()->authnRequest(self::request(), null, 'state-1')));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame([Response::HTTP_BAD_REQUEST, 1], [
            $response->getStatusCode(),
            $this->browser->getCrawler()->filter('[data-error="saml_request_refused"]')->count(),
        ]);
    }

    /**
     * S-18: a reference this browser does not hold names nothing.
     */
    #[Test]
    public function aReferenceTheBrowserDoesNotHoldIsRefused(): void
    {
        // Given
        $this->posted('state-1');

        // When
        $this->browser->request('GET', '/saml/sso/resume', ['request' => 'not-a-reference']);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * S-18: a request answered is forgotten, and no second assertion is written for it.
     */
    #[Test]
    public function aRequestAnsweredIsNotAnsweredAgain(): void
    {
        // Given
        $this->posted('state-1');
        $this->logIn();
        $resume = $this->browser->getHistory()->current()->getUri();

        // When
        $this->browser->request('GET', $resume);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * The request the service provider redirects the browser with, to the path of the single sign-on service on the
     * host of the browser, which holds its cookies.
     */
    private function redirected(string $relayState): void
    {
        $this->browser->request('GET', self::pathOf(new RedirectSender()->authnRequest(self::request(), self::signing(), $relayState)));
    }

    private static function pathOf(string $url): string
    {
        return parse_url($url, PHP_URL_PATH) . '?' . parse_url($url, PHP_URL_QUERY);
    }

    private function posted(string $relayState): void
    {
        $form = new PostSender()->authnRequest(self::request(), self::signing(), $relayState);
        $this->browser->request('POST', '/saml/sso', $form->fields, [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded']);
    }

    /**
     * The browser was sent to the login: it signs in on the form, and follows where the login sends it back.
     */
    private function logIn(): void
    {
        $this->browser->followRedirect();
        $this->submitLogin();
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        $this->browser->followRedirect();
    }

    private function submitLogin(): void
    {
        $form = $this->browser->getCrawler()->selectButton('Sign in')->form();
        $form['_username'] = 'alice';
        $form['_password'] = self::PASSWORD;
        $this->browser->submit($form);
    }

    /**
     * The form of the page, as a browser reads it.
     *
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

    /**
     * The response the page posts, as the service provider validates it: under the certificate the metadata of the
     * tenant publish, at its assertion consumer service, for its entity ID, answering its request.
     */
    private function accepted(): AcceptedAssertion
    {
        $form = $this->form();
        static::assertSame(self::ASSERTION_CONSUMER, $form['action']);

        return new PostReceiver(SamlLoader::create())->response($form['fields'])->validate(
            new ResponseValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
            $this->identityProvider(),
            ExpectedResponse::toRequest(self::requestId(), self::ASSERTION_CONSUMER, self::SERVICE_PROVIDER),
        );
    }

    private function identityProvider(): IdentityProvider
    {
        $this->browser->request('GET', '/saml/metadata');

        return new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(
            SamlLoader::create()->load(self::string($this->browser->getResponse()->getContent())),
        )->identityProvider ?? static::fail('The tenant serves no identity provider.');
    }

    private static function request(): AuthnRequest
    {
        return new AuthnRequest(self::requestId(), self::currentSecond(), new Issuer(self::SERVICE_PROVIDER), self::SINGLE_SIGN_ON, self::ASSERTION_CONSUMER);
    }

    private static function requestId(): string
    {
        return '_4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b';
    }

    private static function signing(): Signing
    {
        return new Signing(MetadataFixtures::signingKey('sp'));
    }
}
