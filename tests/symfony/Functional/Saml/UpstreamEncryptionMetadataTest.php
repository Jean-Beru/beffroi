<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Saml;

use function array_map;
use App\Command\SamlIdentityProviderListCommand;
use App\Saml\IdentityProviderSegment;
use App\Saml\SamlSigning;
use App\Saml\ServiceProviderRoutes;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml\Bridge\Model\UpstreamDecryptionKeys;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Writing\ResponseWriterFixtures;
use Beffroi\Saml2\Model\Writing\Encryption;
use Beffroi\Saml2\Model\Writing\ResponseWriter;
use Beffroi\Saml2\Model\Writing\SignedParts;
use Beffroi\Saml2\Model\Writing\Signing;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Enc\PeerKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use function preg_quote;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * beffroi/saml, spec/saml.md S-64 to S-66, section 6.12
 */
final class UpstreamEncryptionMetadataTest extends ConsoleTestCase
{
    private const string SERVICE_PROVIDER = 'test_service_provider';

    private const string PROVIDER = 'https://idp-a.example/metadata';

    private const string OTHER_PROVIDER = 'https://idp-b.example/metadata';

    private const string DECLARED_PROVIDER = 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/metadata';

    protected static function kernelOptions(): array
    {
        return [
            'environment' => self::SERVICE_PROVIDER,
        ];
    }

    /**
     * S-39, S-65
     */
    #[Test]
    public function theMetadataOfTheEntityIdCarryNoKeyForEncryption(): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::OTHER_PROVIDER);

        // When
        $this->browser->request('GET', ServiceProviderRoutes::METADATA_PATH);

        // Then
        static::assertSame([], $this->servedDescriptor()->serviceProvider?->encryptionCertificates);
    }

    /**
     * S-65
     */
    #[Test]
    #[DataProvider('provideProviders')]
    public function eachProviderIsGivenTheCertificateOfItsOwnKey(string $provider): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        $keys = [
            self::PROVIDER => self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER),
            self::OTHER_PROVIDER => self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::OTHER_PROVIDER),
        ];

        // When
        $this->browser->request('GET', self::metadataOf($provider));

        // Then
        static::assertSame(
            [CertificateModulus::ofKey($keys[$provider])],
            array_map(CertificateModulus::ofCertificate(...), $this->servedDescriptor()->serviceProvider->encryptionCertificates ?? []),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideProviders(): iterable
    {
        yield 'the first' => [self::PROVIDER];
        yield 'the second' => [self::OTHER_PROVIDER];
    }

    /**
     * S-64, S-65
     */
    #[Test]
    public function theProviderTheConfigurationDeclaresIsGivenTheCertificateOfItsKey(): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        $key = self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::DECLARED_PROVIDER);

        // When
        $this->browser->request('GET', self::metadataOf(self::DECLARED_PROVIDER));

        // Then
        static::assertSame(
            [CertificateModulus::ofKey($key)],
            array_map(CertificateModulus::ofCertificate(...), $this->servedDescriptor()->serviceProvider->encryptionCertificates ?? []),
        );
    }

    /**
     * S-65
     */
    #[Test]
    public function theUrlTheListCommandPrintsServesTheCertificateOfTheKeyOfTheProvider(): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        $key = self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::DECLARED_PROVIDER);
        $url = self::displayed(self::console(SamlIdentityProviderListCommand::NAME), preg_quote(self::DECLARED_PROVIDER, '/'));

        // When
        $this->browser->request('GET', $url);

        // Then
        static::assertSame(
            [CertificateModulus::ofKey($key)],
            array_map(CertificateModulus::ofCertificate(...), $this->servedDescriptor()->serviceProvider->encryptionCertificates ?? []),
        );
    }

    /**
     * Section 6.12 step 5
     */
    #[Test]
    public function theyAreServedAsSamlMetadataForTheMaxAgeOfTheKeys(): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);

        // When
        $this->browser->request('GET', self::metadataOf(self::PROVIDER));

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
     * S-65
     */
    #[Test]
    #[DataProvider('provideUrlsOfNoMetadata')]
    public function noMetadataIsGivenWhereNoProviderHoldsAKey(string $url): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);

        // When
        $this->browser->request('GET', $url);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUrlsOfNoMetadata(): iterable
    {
        yield 'a provider nothing wires' => ['/saml/sp/metadata/' . IdentityProviderSegment::of('https://idp-c.example/metadata')];
        yield 'a provider without a key' => ['/saml/sp/metadata/' . IdentityProviderSegment::of(self::OTHER_PROVIDER)];
        yield 'a segment that is not base64url' => ['/saml/sp/metadata/aHR0cHM6Ly9pZHAtYS5leGFtcGxlL21ldGFkYXRh='];
        yield 'a segment that names no entity ID' => ['/saml/sp/metadata/' . IdentityProviderSegment::of('not an entity ID')];
    }

    /**
     * S-64
     */
    #[Test]
    public function theJwkSetDoesNotCarryTheKeyOfAProvider(): void
    {
        // Given
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);

        // When
        $this->browser->request('GET', '/jwks');

        // Then
        static::assertSame([], self::json($this->browser->getResponse())['keys'] ?? null);
    }

    /**
     * S-66
     */
    #[Test]
    public function theKeyOfAProviderOpensWhatWasEncryptedForTheCertificateServed(): void
    {
        // Given
        self::generate(SamlSigning::NAME);
        self::generate(SamlEncryptionAlgorithmInterface::NAME_PREFIX . self::PROVIDER);
        $this->browser->request('GET', self::metadataOf(self::PROVIDER));
        $certificate = $this->servedDescriptor()->serviceProvider->encryptionCertificates[0] ?? static::fail('No certificate was served.');
        $response = ResponseWriterFixtures::response();
        $encrypted = new ResponseWriter()->write(
            $response,
            new Signing(MetadataFixtures::signingKey('idp')),
            SignedParts::AssertionAndResponse,
            new Encryption(PeerKey::fromCertificateBase64($certificate)),
        );

        // When
        $key = self::service('test.beffroi.upstream_decryption_keys', UpstreamDecryptionKeys::class)->of(
            self::tenant(),
            self::PROVIDER,
        ) ?? static::fail('The provider is given no key.');
        $accepted = ResponseWriterFixtures::validator()->validate(
            UnverifiedResponse::of(SamlLoader::create()->load(new Serializer()->serialize($encrypted))),
            ResponseWriterFixtures::identityProvider()->withDecryptionKey($key),
            ResponseWriterFixtures::expected(),
        );

        // Then
        static::assertEquals($response->assertion, $accepted->assertion);
    }

    private static function metadataOf(string $provider): string
    {
        return self::service('router', UrlGeneratorInterface::class)
            ->generate(ServiceProviderRoutes::METADATA_FOR_IDENTITY_PROVIDER, [
                'identityProvider' => IdentityProviderSegment::of($provider),
            ]);
    }

    private static function generate(string $algorithm): TenantKey
    {
        $tester = self::console('beffroi:keys:generate', [
            '--algorithm' => $algorithm,
        ]);
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        foreach (self::service('test.beffroi.keys', TenantKeyRepositoryInterface::class)->findInService(self::tenant()) as $key) {
            if ($key->algorithm->name() === $algorithm) {
                return $key;
            }
        }

        return static::fail('The command drew no key.');
    }

    private function servedDescriptor(): EntityDescriptor
    {
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());

        return new MetadataReader(SamlLoader::create(), new MockClock())->readTrusted(SamlLoader::create()->load(self::string($response->getContent())));
    }
}
