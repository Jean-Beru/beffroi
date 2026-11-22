<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Bridge\Model\ModelAuthnRequestParties;
use Beffroi\Saml\Domain\ServiceProvider\AuthnRequestSigning;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\SignatureRequired;
use Beffroi\Saml2\Model\Exception\UnknownEndpoint;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider as ModelServiceProvider;
use Beffroi\Saml2\Model\Protocol\UnverifiedAuthnRequest;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Unit\Metadata\MetadataFixtures;
use Beffroi\Saml2\Model\Tests\Unit\Validation\AuthnRequestFixtures;
use Beffroi\Saml2\Model\Validation\Authentication;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\Clock\MockClock;

/**
 * spec/saml.md S-9, S-10, section 6.3 steps 3 to 5
 */
final class ModelAuthnRequestPartiesTest extends TestCase
{
    private const string ELSEWHERE = 'https://attacker.example.net/acs';

    /**
     * S-9
     */
    #[Test]
    public function itAcceptsAnUnsignedRequestFromAProviderDeclaredUnsigned(): void
    {
        // Given
        $parties = self::entraParties(signsAuthnRequests: false);

        // When
        $accepted = AuthnRequestFixtures::validator()->validate(
            self::entraRequest(ServiceProviderDocuments::ENTRA_ASSERTION_CONSUMER),
            $parties->serviceProvider,
            $parties->identityProvider,
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );

        // Then
        static::assertSame(Authentication::None, $accepted->authentication);
        static::assertSame(ServiceProviderDocuments::ENTRA_ASSERTION_CONSUMER, $accepted->assertionConsumerService->location);
    }

    /**
     * S-9
     */
    #[Test]
    public function itRefusesAnUnsignedRequestFromAProviderNotDeclaredUnsigned(): void
    {
        // Given
        $parties = self::entraParties(signsAuthnRequests: true);

        // Then
        $this->expectException(SignatureRequired::class);

        // When
        AuthnRequestFixtures::validator()->validate(
            self::entraRequest(ServiceProviderDocuments::ENTRA_ASSERTION_CONSUMER),
            $parties->serviceProvider,
            $parties->identityProvider,
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * S-9, the second row of section 6.3 step 2
     */
    #[Test]
    public function itRefusesAnUnsignedRequestFromAProviderWhoseMetadataSayItSigns(): void
    {
        // Given
        $parties = self::entraParties(signsAuthnRequests: false, document: ServiceProviderDocuments::entraSigningItsRequests());

        // Then
        $this->expectException(SignatureRequired::class);

        // When
        AuthnRequestFixtures::validator()->validate(
            self::entraRequest(ServiceProviderDocuments::ENTRA_ASSERTION_CONSUMER),
            $parties->serviceProvider,
            $parties->identityProvider,
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * S-10, M-9
     */
    #[Test]
    public function itRefusesAnAssertionConsumerServiceOutsideTheMetadataOfAProviderDeclaredUnsigned(): void
    {
        // Given
        $parties = self::entraParties(signsAuthnRequests: false);

        // Then
        $this->expectException(UnknownEndpoint::class);

        // When
        AuthnRequestFixtures::validator()->validate(
            self::entraRequest(self::ELSEWHERE),
            $parties->serviceProvider,
            $parties->identityProvider,
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * S-10, M-9
     */
    #[Test]
    public function itRefusesAnAssertionConsumerServiceOutsideTheMetadataOfAProviderThatSigns(): void
    {
        // Given
        $serviceProvider = new ModelServiceProvider(
            AuthnRequestFixtures::SERVICE_PROVIDER,
            [MetadataFixtures::certificate('sp')],
            [],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, AuthnRequestFixtures::ASSERTION_CONSUMER . '/elsewhere', 0)]),
        );
        $parties = new ModelAuthnRequestParties(
            self::signing(AuthnRequestFixtures::SERVICE_PROVIDER, true, false),
            $serviceProvider,
            AuthnRequestFixtures::identityProvider(true),
        );

        // Then
        $this->expectException(UnknownEndpoint::class);

        // When
        AuthnRequestFixtures::validator()->validate(
            AuthnRequestFixtures::load('behaviour/authn-request-signed.xml'),
            $parties->serviceProvider,
            $parties->identityProvider,
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );
    }

    /**
     * S-9, M-2
     */
    #[Test]
    public function itAcceptsASignedRequestFromAProviderThatSigns(): void
    {
        // Given
        $parties = new ModelAuthnRequestParties(
            self::signing(AuthnRequestFixtures::SERVICE_PROVIDER, true, false),
            AuthnRequestFixtures::serviceProvider(),
            AuthnRequestFixtures::identityProvider(),
        );

        // When
        $accepted = AuthnRequestFixtures::validator()->validate(
            AuthnRequestFixtures::load('behaviour/authn-request-signed.xml'),
            $parties->serviceProvider,
            $parties->identityProvider,
            AuthnRequestFixtures::SINGLE_SIGN_ON,
        );

        // Then
        static::assertSame(Authentication::XmlSignature, $accepted->authentication);
    }

    /**
     * Section 6.3 step 3
     */
    #[Test]
    public function itSetsTheRequirementOnBothPartiesAndKeepsTheRest(): void
    {
        // Given
        $serviceProvider = new ModelServiceProvider(
            AuthnRequestFixtures::SERVICE_PROVIDER,
            [MetadataFixtures::certificate('sp')],
            [MetadataFixtures::certificate('idp')],
            new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, AuthnRequestFixtures::ASSERTION_CONSUMER, 0)]),
            [new Endpoint(Binding::HttpRedirect, AuthnRequestFixtures::SERVICE_PROVIDER . '/slo')],
            [NameIdFormat::Persistent],
            false,
            true,
        );
        $identityProvider = new IdentityProvider(
            AuthnRequestFixtures::IDENTITY_PROVIDER,
            [MetadataFixtures::certificate('idp')],
            [MetadataFixtures::certificate('sp')],
            [new Endpoint(Binding::HttpRedirect, AuthnRequestFixtures::SINGLE_SIGN_ON)],
            [new Endpoint(Binding::HttpPost, AuthnRequestFixtures::IDENTITY_PROVIDER . '/slo')],
            [NameIdFormat::Transient],
            false,
        );

        // When
        $parties = new ModelAuthnRequestParties(self::signing(AuthnRequestFixtures::SERVICE_PROVIDER, true, false), $serviceProvider, $identityProvider);

        // Then
        static::assertEquals(
            new ModelServiceProvider(
                AuthnRequestFixtures::SERVICE_PROVIDER,
                [MetadataFixtures::certificate('sp')],
                [MetadataFixtures::certificate('idp')],
                new IndexedEndpoints([new IndexedEndpoint(Binding::HttpPost, AuthnRequestFixtures::ASSERTION_CONSUMER, 0)]),
                [new Endpoint(Binding::HttpRedirect, AuthnRequestFixtures::SERVICE_PROVIDER . '/slo')],
                [NameIdFormat::Persistent],
                true,
                true,
            ),
            $parties->serviceProvider,
        );
        static::assertEquals(
            new IdentityProvider(
                AuthnRequestFixtures::IDENTITY_PROVIDER,
                [MetadataFixtures::certificate('idp')],
                [MetadataFixtures::certificate('sp')],
                [new Endpoint(Binding::HttpRedirect, AuthnRequestFixtures::SINGLE_SIGN_ON)],
                [new Endpoint(Binding::HttpPost, AuthnRequestFixtures::IDENTITY_PROVIDER . '/slo')],
                [NameIdFormat::Transient],
                true,
            ),
            $parties->identityProvider,
        );
    }

    /**
     * Section 6.3 step 3
     */
    #[Test]
    public function itRefusesAServiceProviderOfAnotherEntity(): void
    {
        // Given
        $signing = self::signing(ServiceProviderDocuments::ENTRA, false, false);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The signature a request needs applies to the service provider it was read for (spec/saml.md section 6.3 step 3).');

        // When
        new ModelAuthnRequestParties($signing, AuthnRequestFixtures::serviceProvider(), AuthnRequestFixtures::identityProvider());
    }

    /**
     * S-9
     */
    #[Test]
    public function itRefusesAServiceProviderThatSignsUnderARequirementThatSaysNone(): void
    {
        // Given
        $signing = self::signing(AuthnRequestFixtures::SERVICE_PROVIDER, false, false);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A service provider whose metadata say it signs its requests needs their signature (spec/saml.md S-9).');

        // When
        new ModelAuthnRequestParties($signing, AuthnRequestFixtures::serviceProvider(authnRequestsSigned: true), AuthnRequestFixtures::identityProvider());
    }

    private static function signing(string $entityId, bool $signsAuthnRequests, bool $authnRequestsSigned): AuthnRequestSigning
    {
        return AuthnRequestSigning::of(
            new ServiceProvider($entityId, new MetadataLocation('/etc/beffroi/sp.xml'), signsAuthnRequests: $signsAuthnRequests),
            new ServiceProviderMetadata($entityId, null, [], $authnRequestsSigned, [], readSigned: false),
        );
    }

    private static function entraParties(bool $signsAuthnRequests, ?string $document = null): ModelAuthnRequestParties
    {
        $loader = SamlLoader::create();
        $serviceProvider = new MetadataReader($loader, new MockClock(new DateTimeImmutable(AuthnRequestFixtures::NOW)))->readTrusted($loader->load(
            $document ?? ServiceProviderDocuments::entra(),
        ))->serviceProvider;
        static::assertInstanceOf(ModelServiceProvider::class, $serviceProvider);

        return new ModelAuthnRequestParties(
            self::signing(ServiceProviderDocuments::ENTRA, $signsAuthnRequests, $serviceProvider->authnRequestsSigned),
            $serviceProvider,
            AuthnRequestFixtures::identityProvider(wantAuthnRequestsSigned: true),
        );
    }

    private static function entraRequest(string $assertionConsumerServiceUrl): UnverifiedAuthnRequest
    {
        return AuthnRequestFixtures::request(
            ['AssertionConsumerServiceURL' => $assertionConsumerServiceUrl],
            sprintf('<saml:Issuer>%s</saml:Issuer>', ServiceProviderDocuments::ENTRA),
        );
    }
}
