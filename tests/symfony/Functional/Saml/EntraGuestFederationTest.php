<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use App\Saml\SamlSigning;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml\Tests\Fixture\SignatureCertificates;
use Beffroi\Saml2\Bindings\PostReceiver;
use Beffroi\Saml2\Bindings\PostSender;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\NameIdPolicy;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use function array_combine;
use function array_map;
use function base64_decode;
use DOMDocument;
use DOMXPath;
use function http_build_query;
use function parse_url;
use const PHP_URL_PATH;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * beffroi/saml, spec/saml.md section 7, section 6.4
 */
final class EntraGuestFederationTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = ServiceProviderDocuments::ENTRA;

    private const string ASSERTION_CONSUMER = ServiceProviderDocuments::ENTRA_ASSERTION_CONSUMER;

    private const string EMAIL_ADDRESS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';

    private const string SINGLE_SIGN_ON = 'https://op.test/saml/sso';

    private User $alice;

    protected function setUp(): void
    {
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
                ServiceProviderDocuments::entra(),
                null,
                self::currentSecond(),
            ));
        $this->alice = self::userWithPassword('alice', 'correct horse battery staple');
        $this->alice->changeEmail(new EmailAddress('alice@example.com'), true, self::currentSecond());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($this->alice);
    }

    /**
     * Section 7, S-9, S-14, S-16
     */
    #[Test]
    public function anUnsignedRequestOverHttpRedirectGetsTheAssertionEntraExpects(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->redirected();

        // Then
        $assertion = $this->accepted()->assertion;
        static::assertSame(
            [
                [[self::SERVICE_PROVIDER]],
                self::ASSERTION_CONSUMER,
                NameIdFormat::Persistent->value,
                self::SERVICE_PROVIDER,
                [self::EMAIL_ADDRESS => ['alice@example.com']],
            ],
            [
                $assertion->conditions->audiences,
                $assertion->confirmation->recipient,
                $assertion->nameId->format->value,
                $assertion->nameId->spNameQualifier,
                array_combine(
                    array_map(static fn ($attribute): string => $attribute->name, $assertion->attributes),
                    array_map(static fn ($attribute): array => $attribute->values, $assertion->attributes),
                ),
            ],
        );
    }

    /**
     * Section 7, S-15
     */
    #[Test]
    public function theConditionsOfTheAssertionBeginAtItsIssue(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->redirected();

        // Then
        $assertion = $this->accepted()->assertion;
        static::assertSame($assertion->issueInstant->format('c'), $assertion->conditions->notBefore?->format('c'));
    }

    /**
     * Section 7, S-28
     */
    #[Test]
    public function anUnsignedRequestPostedFromEntraIsAnsweredFromTheSession(): void
    {
        // Given
        $this->signIn($this->alice);
        $this->postedFromAnotherSite('/saml/sso', http_build_query(new PostSender()->authnRequest(self::request(), null)->fields));

        // When
        $this->postedAgain();

        // Then
        static::assertSame(SignatureCoverage::AssertionAndResponse, $this->accepted()->coverage);
    }

    /**
     * Section 7, S-15
     */
    #[Test]
    public function theResponseAndTheAssertionAreSignedAsMicrosoftDocumentsIt(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->redirected();

        // Then
        $response = self::string(base64_decode($this->form()['fields']['SAMLResponse'] ?? '', true));
        $document = new DOMDocument();
        static::assertTrue($document->loadXML($response === '' ? static::fail('The form posts no SAMLResponse.') : $response));
        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $signatures = ['count' => $xpath->evaluate('count(//ds:Signature)')];
        foreach (['Response' => '/samlp:Response/ds:Signature', 'Assertion' => '/samlp:Response/saml:Assertion/ds:Signature'] as $signed => $signature) {
            $signatures[$signed] = [
                $xpath->evaluate(sprintf('string(%s/ds:SignedInfo/ds:SignatureMethod/@Algorithm)', $signature)),
                $xpath->evaluate(sprintf('string(%s/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm)', $signature)),
                [
                    $xpath->evaluate(sprintf('count(%s/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform)', $signature)),
                    $xpath->evaluate(sprintf('string(%s/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[1]/@Algorithm)', $signature)),
                    $xpath->evaluate(sprintf('string(%s/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[2]/@Algorithm)', $signature)),
                ],
            ];
        }
        $expected = [
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'http://www.w3.org/2001/04/xmlenc#sha256',
            [2.0, 'http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
        ];
        static::assertSame(['count' => 2.0, 'Response' => $expected, 'Assertion' => $expected], $signatures);
    }

    /**
     * Section 7, S-37
     */
    #[Test]
    public function eachSignatureCarriesTheCertificateOfTheMetadataServed(): void
    {
        // Given
        $this->signIn($this->alice);
        $served = $this->identityProvider()->signingCertificates;

        // When
        $this->redirected();

        // Then
        $response = SamlLoader::create()->load(self::string(base64_decode($this->form()['fields']['SAMLResponse'] ?? '', true)));
        static::assertSame([$served, $served], SignatureCertificates::of($response));
    }

    /**
     * Section 7, S-36, section 12
     */
    #[Test]
    public function thePageLetsLoginSrfSendTheBrowserOn(): void
    {
        // Given
        $this->signIn($this->alice);

        // When
        $this->redirected();

        // Then
        static::assertSame(
            "default-src 'none'; script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; base-uri 'none'; frame-ancestors 'none'",
            $this->browser->getResponse()->headers->get('Content-Security-Policy'),
        );
    }

    private function redirected(): void
    {
        $url = new RedirectSender()->authnRequest(self::request(), null);
        $this->browser->request('GET', parse_url($url, PHP_URL_PATH) . '?' . parse_url($url, PHP_URL_QUERY));
    }

    private static function request(): AuthnRequest
    {
        return new AuthnRequest(
            self::requestId(),
            self::currentSecond(),
            new Issuer(self::SERVICE_PROVIDER),
            self::SINGLE_SIGN_ON,
            nameIdPolicy: new NameIdPolicy(NameIdFormat::Persistent->value),
        );
    }

    private static function requestId(): string
    {
        return '_1e089e5c-a976-4881-af74-3b92c89e7e2c';
    }

    private function accepted(): AcceptedAssertion
    {
        $form = $this->form();
        static::assertSame(self::ASSERTION_CONSUMER, $form['action']);

        return new PostReceiver(SamlLoader::create())
            ->response($form['fields'])
            ->validate(
                new ResponseValidator(SamlLoader::create(), new MockClock(self::currentSecond()), new InMemoryReplayGuard()),
                $this->identityProvider(),
                ExpectedResponse::toRequest(self::requestId(), self::ASSERTION_CONSUMER, self::SERVICE_PROVIDER),
            );
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
}
