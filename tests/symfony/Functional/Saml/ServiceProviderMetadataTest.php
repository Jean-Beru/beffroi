<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use App\Saml\SamlSigning;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml2\Bindings\RedirectSender;
use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Assertion\NameId;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\AuthnRequest;
use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Writing\Signing;
use function array_map;
use function parse_url;
use const PHP_URL_PATH;
use const PHP_URL_QUERY;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;

/**
 * beffroi/saml, spec/saml.md S-38 to S-41, section 6.9
 */
final class ServiceProviderMetadataTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = 'test_service_provider';

    private const string METADATA = '/saml/sp/metadata';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    /**
     * Section 6.9, S-38, S-39
     */
    #[Test]
    public function theMetadataOfTheServiceProviderAreReadBackByTheModel(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        $descriptor = $this->servedDescriptor();
        $serviceProvider = $descriptor->serviceProvider;
        static::assertNotNull($serviceProvider);
        static::assertEquals(
            [
                'https://op.test/saml/sp/metadata',
                null,
                [new IndexedEndpoint(Binding::HttpPost, 'https://op.test/saml/sp/acs', 0)],
                true,
                true,
                1,
                [],
                [],
            ],
            [
                $descriptor->entityId,
                $descriptor->identityProvider,
                $serviceProvider->assertionConsumerServices->endpoints,
                $serviceProvider->authnRequestsSigned,
                $serviceProvider->wantAssertionsSigned,
                \count($serviceProvider->signingCertificates),
                $serviceProvider->encryptionCertificates,
                $serviceProvider->singleLogoutServices,
            ],
        );
    }

    /**
     * Section 6.9 step 5
     */
    #[Test]
    public function theyAreServedAsSamlMetadataForTheMaxAgeOfTheKeys(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(
            ['application/samlmetadata+xml', true, '120'],
            [
                $response->headers->get('Content-Type'),
                $response->headers->hasCacheControlDirective('public'),
                $response->headers->getCacheControlDirective('max-age'),
            ],
        );
    }

    /**
     * S-40
     */
    #[Test]
    public function theCertificateIsAroundTheSamlKeyTheServiceProviderDrew(): void
    {
        // Given
        $key = self::generate();

        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        static::assertSame(
            [CertificateModulus::ofKey($key)],
            array_map(CertificateModulus::ofCertificate(...), $this->servedDescriptor()->serviceProvider->signingCertificates ?? []),
        );
    }

    /**
     * S-41
     */
    #[Test]
    public function theIdentityProviderLeftOffServesNoMetadata(): void
    {
        // Given
        self::generate();

        // When
        $this->browser->request('GET', '/saml/metadata');

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * S-41
     */
    #[Test]
    public function theIdentityProviderLeftOffRefusesEveryRequest(): void
    {
        // Given
        self::generate();
        $request = new AuthnRequest(
            '_5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c',
            Clock::get()->now(),
            new Issuer('https://sp.example.org/saml'),
            'https://op.test/saml/sso',
            'https://sp.example.org/saml/acs',
        );
        $url = new RedirectSender()->authnRequest($request, new Signing(MetadataFixtures::signingKey('sp')), 'state-1');

        // When
        $this->browser->request('GET', parse_url($url, PHP_URL_PATH) . '?' . parse_url($url, PHP_URL_QUERY));

        // Then
        static::assertSame([Response::HTTP_BAD_REQUEST, 1], [
            $this->browser->getResponse()->getStatusCode(),
            $this->browser->getCrawler()->filter('[data-error="saml_request_refused"]')->count(),
        ]);
    }

    /**
     * Section 6.9 step 1
     */
    #[Test]
    public function aTenantWithoutASamlKeyServesNoMetadata(): void
    {
        // When
        $this->browser->request('GET', self::METADATA);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * S-41
     */
    #[Test]
    public function theIdentityProviderLeftOffRefusesEveryLogoutRequest(): void
    {
        // Given
        self::generate();
        $request = new LogoutRequest(
            '_6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d',
            Clock::get()->now(),
            new Issuer('https://sp.example.org/saml'),
            'https://op.test/saml/slo',
            null,
            new NameId('a-persistent-identifier', NameIdFormat::Persistent),
            ['0199f0a1-7b2c-7d3e-8f4a-5b6c7d8e9f0a'],
        );
        $url = new RedirectSender()->logoutRequest($request, new Signing(MetadataFixtures::signingKey('sp')), 'state-1');

        // When
        $this->browser->request('GET', parse_url($url, PHP_URL_PATH) . '?' . parse_url($url, PHP_URL_QUERY));

        // Then
        static::assertSame([Response::HTTP_BAD_REQUEST, 1], [
            $this->browser->getResponse()->getStatusCode(),
            $this->browser->getCrawler()->filter('[data-error="saml_logout_refused"]')->count(),
        ]);
    }

    private static function generate(): TenantKey
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => SamlSigning::NAME,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());

        return (
            self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)
                ->findInService(self::tenant())[0] ?? static::fail('The command drew no key.')
        );
    }

    private function servedDescriptor(): EntityDescriptor
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());

        return new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(SamlLoader::create()->load(self::string($response->getContent())));
    }
}
