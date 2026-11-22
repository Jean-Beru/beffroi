<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Model\ModelUpstreamMetadataReader;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Tests\Fixture\IdentityProviderDocuments;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * spec/saml.md S-42, S-43, section 6.10 step 3, S-48, section 6.11 step 4
 */
final class ModelUpstreamMetadataReaderTest extends TestCase
{
    private ModelUpstreamMetadataReader $reader;

    protected function setUp(): void
    {
        $this->reader = new ModelUpstreamMetadataReader(new MockClock(Fixtures::now()));
    }

    #[Test]
    public function itReadsTheMetadataOfTheIdentityProviderOfTheJudge(): void
    {
        // When
        $metadata = $this->reader->readTrusted(IdentityProviderDocuments::simpleSamlPhp());

        // Then
        static::assertSame(IdentityProviderDocuments::SIMPLESAMLPHP, $metadata->entityId);
        static::assertNull($metadata->validUntil);
        static::assertCount(1, $metadata->signingCertificates);
        static::assertStringStartsWith('MIIDczCCAlugAwIBAgIUa0/lzw/yMB2B', $metadata->signingCertificates[0]->base64);
        static::assertFalse($metadata->readSigned);
    }

    /**
     * S-42, S-6
     */
    #[Test]
    public function itReadsADocumentSignedByThePinnedKey(): void
    {
        // When
        $metadata = $this->reader->readSigned(
            IdentityProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')),
            [IdentityProviderDocuments::signer()],
        );

        // Then
        static::assertSame(IdentityProviderDocuments::SIGNED, $metadata->entityId);
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $metadata->validUntil);
        static::assertTrue($metadata->readSigned);
    }

    /**
     * S-42
     */
    #[Test]
    public function itRefusesADocumentSignedByAnotherKey(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);

        // When
        $this->reader->readSigned(
            IdentityProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z'), 'sp'),
            [IdentityProviderDocuments::signer()],
        );
    }

    /**
     * S-6
     */
    #[Test]
    public function itRefusesASignedDocumentWithoutValidUntil(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('Signed metadata carry a validUntil, without which an older document signed by the same key verifies as well (spec/saml.md S-6).');

        // When
        $this->reader->readSigned(IdentityProviderDocuments::signed(null), [IdentityProviderDocuments::signer()]);
    }

    /**
     * S-42
     */
    #[Test]
    public function itRefusesADocumentWithoutAnIdentityProviderRole(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The metadata hold no identity provider role of SAML 2.0 (spec/saml.md S-42).');

        // When
        $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhp());
    }

    /**
     * S-43
     */
    #[Test]
    public function itRefusesAnIdentityProviderWithoutAKeyForSigning(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The metadata of the identity provider hold no key for signing, and nothing it sends could be verified (spec/saml.md S-43).');

        // When
        $this->reader->readTrusted(IdentityProviderDocuments::simpleSamlPhpWithoutSigningKey());
    }

    /**
     * S-43, M-16
     */
    #[Test]
    #[DataProvider('provideSingleSignOnServicesOutOfReach')]
    public function itRefusesASingleSignOnServiceThatIsNotHttpsOnAHost(string $location): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The Location of an md:SingleSignOnService is not an https URL on a host name or an IP address, and the service provider sends a browser there (spec/saml.md S-43).');

        // When
        $this->reader->readTrusted(IdentityProviderDocuments::simpleSamlPhpSigningOnAt($location));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSingleSignOnServicesOutOfReach(): iterable
    {
        yield 'plain http' => ['http://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService'];
        yield 'a script' => ['javascript:alert(1)'];
        yield 'a semicolon in the host' => ['https://idp.example;sandbox/sso'];
    }

    /**
     * S-43
     */
    #[Test]
    #[DataProvider('provideSingleSignOnServicesInReach')]
    public function itReadsASingleSignOnServiceThatIsHttpsOnAHost(string $location): void
    {
        // When
        $metadata = $this->reader->readTrusted(IdentityProviderDocuments::simpleSamlPhpSigningOnAt($location));

        // Then
        static::assertSame(IdentityProviderDocuments::SIMPLESAMLPHP, $metadata->entityId);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSingleSignOnServicesInReach(): iterable
    {
        yield 'a port' => ['https://saml-idp.localhost:8443/sso'];
        yield 'an IPv6 literal' => ['https://[2001:db8::1]/sso'];
    }

    /**
     * S-48, section 6.11 step 4
     */
    #[Test]
    public function itReadsTheAcceptedDocumentBackIntoTheRoleOfTheModel(): void
    {
        // When
        $role = $this->reader->readAccepted(IdentityProviderDocuments::simpleSamlPhp());

        // Then
        static::assertSame(IdentityProviderDocuments::SIMPLESAMLPHP, $role->entityId);
        static::assertEquals(
            [new Endpoint(Binding::HttpRedirect, 'https://saml-idp.localhost/simplesaml/module.php/saml/idp/singleSignOnService')],
            $role->singleSignOnServices,
        );
    }

    /**
     * S-42, S-43, section 6.11 step 4
     */
    #[Test]
    #[DataProvider('provideDocumentsTheReadingBackRefuses')]
    public function itRefusesAtTheReadingBackWhatAReadingRefuses(string $document, string $message): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->reader->readAccepted($document);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideDocumentsTheReadingBackRefuses(): iterable
    {
        yield 'no identity provider role' => [
            ServiceProviderDocuments::simpleSamlPhp(),
            'The metadata hold no identity provider role of SAML 2.0 (spec/saml.md S-42).',
        ];
        yield 'no key for signing' => [
            IdentityProviderDocuments::simpleSamlPhpWithoutSigningKey(),
            'The metadata of the identity provider hold no key for signing, and nothing it sends could be verified (spec/saml.md S-43).',
        ];
        yield 'a single sign-on service in plain http' => [
            IdentityProviderDocuments::simpleSamlPhpSigningOnAt('http://saml-idp.localhost/sso'),
            'The Location of an md:SingleSignOnService is not an https URL on a host name or an IP address, and the service provider sends a browser there (spec/saml.md S-43).',
        ];
    }
}
