<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use function substr;

/**
 * spec/saml.md S-5, S-6, section 6.2 steps 3 and 4
 */
final class ModelServiceProviderMetadataReaderTest extends TestCase
{
    private const string ASSERTION_CONSUMER = 'https://sp.example.org/saml/acs';

    private ModelServiceProviderMetadataReader $reader;

    protected function setUp(): void
    {
        $this->reader = new ModelServiceProviderMetadataReader(new MockClock(Fixtures::now()));
    }

    #[Test]
    public function itReadsTheMetadataOfASimpleSamlPhpServiceProvider(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertSame(ServiceProviderDocuments::SIMPLESAMLPHP, $metadata->entityId);
        static::assertNull($metadata->validUntil);
        static::assertCount(1, $metadata->encryptionCertificates);
        static::assertStringStartsWith('MIIDcTCCAlmgAwIBAgIUcUbLWObVO2r2', $metadata->encryptionCertificates[0]->base64);
    }

    /**
     * S-9, section 6.2 step 3
     */
    #[Test]
    public function itReadsThatAServiceProviderSignsItsRequests(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertTrue($metadata->authnRequestsSigned);
    }

    /**
     * S-9, section 6.2 step 3, Metadata §2.4.4
     */
    #[Test]
    public function itReadsAnAbsentAuthnRequestsSignedAsFalse(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::entra());

        // Then
        static::assertSame(ServiceProviderDocuments::ENTRA, $metadata->entityId);
        static::assertFalse($metadata->authnRequestsSigned);
        static::assertSame([], $metadata->encryptionCertificates);
    }

    /**
     * S-11, section 6.2 step 3
     */
    #[Test]
    public function itReadsTheSigningCertificatesOfADocument(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertCount(1, $metadata->signingCertificates);
    }

    /**
     * S-11, section 6.2 step 3
     */
    #[Test]
    public function itDoesNotReadAnEncryptionCertificateAsASigningOne(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhpWithoutSigningKey());

        // Then
        static::assertSame([], $metadata->signingCertificates);
        static::assertCount(1, $metadata->encryptionCertificates);
    }

    /**
     * S-11, section 6.2 step 3
     */
    #[Test]
    public function itReadsADocumentWithoutAKeyAsHoldingNoSigningCertificate(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::entra());

        // Then
        static::assertSame([], $metadata->signingCertificates);
    }

    #[Test]
    public function itReadsTheValidUntilOfADocument(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));

        // Then
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $metadata->validUntil);
    }

    /**
     * S-6, M-7
     */
    #[Test]
    public function itRefusesAnExpiredDocument(): void
    {
        // Given
        $document = ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-09-15T09:57:00Z');

        // When
        try {
            $this->reader->readTrusted($document);
            static::fail('An expired document is read.');
        } catch (MetadataRefusedException $exception) {
            // Then
            static::assertSame('The metadata is past its validUntil (M-7).', $exception->getMessage());
            static::assertInstanceOf(OutsideValidityWindow::class, $exception->getPrevious());
        }
    }

    /**
     * Section 5.1
     */
    #[Test]
    public function itRefusesACertificateThatIsNotCanonicalBase64(): void
    {
        // Given
        $certificate = ServiceProviderDocuments::signer()->base64;
        $document = ServiceProviderDocuments::simpleSamlPhpWithCertificate(substr($certificate, 0, -3) . 'x==');

        // When
        try {
            $this->reader->readTrusted($document);
            static::fail('A certificate in another spelling is read.');
        } catch (MetadataRefusedException $exception) {
            // Then
            static::assertSame(
                'A certificate is the base64 of its DER, in the alphabet of RFC 4648 section 4 (spec/saml.md section 5.1).',
                $exception->getMessage(),
            );
            static::assertInstanceOf(InvalidArgumentException::class, $exception->getPrevious());
        }
    }

    /**
     * S-5
     */
    #[Test]
    public function itRefusesADocumentWithoutAServiceProviderRole(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The metadata hold no service provider role of SAML 2.0 (spec/saml.md S-5).');

        // When
        $this->reader->readTrusted(ServiceProviderDocuments::identityProvider());
    }

    /**
     * Section 6.2 step 3
     */
    #[Test]
    public function itRefusesWhatCoreRefuses(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The input is empty (I-3).');

        // When
        $this->reader->readTrusted('');
    }

    /**
     * S-5
     */
    #[Test]
    public function itReadsADocumentSignedByAPinnedKey(): void
    {
        // When
        $metadata = $this->reader->readSigned(
            ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')),
            [ServiceProviderDocuments::signer()],
        );

        // Then
        static::assertSame(ServiceProviderDocuments::SIGNED, $metadata->entityId);
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $metadata->validUntil);
    }

    /**
     * S-6
     */
    #[Test]
    public function itSaysADocumentReadUnderAPinnedKeyWasReadSigned(): void
    {
        // When
        $metadata = $this->reader->readSigned(
            ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')),
            [ServiceProviderDocuments::signer()],
        );

        // Then
        static::assertTrue($metadata->readSigned);
    }

    /**
     * S-6
     */
    #[Test]
    public function itSaysADocumentReadByItsChannelWasNotReadSigned(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertFalse($metadata->readSigned);
    }

    /**
     * S-11, M-16, findings B-3, C-2, C-3 of the security review of 20 October 2026
     *
     * @param list<Endpoint> $singleLogoutServices
     */
    #[Test]
    #[DataProvider('provideDocumentsWithAnEndpointOffTheWeb')]
    public function itRefusesADocumentAnEndpointOfWhichIsNotHttpsOnAHost(string $assertionConsumerService, array $singleLogoutServices, string $message): void
    {
        // Given
        $document = ServiceProviderDocuments::signed(
            new DateTimeImmutable('2026-10-01T00:00:00Z'),
            singleLogoutServices: $singleLogoutServices,
            assertionConsumerService: $assertionConsumerService,
        );

        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $this->reader->readTrusted($document);
    }

    /**
     * @return iterable<string, array{string, list<Endpoint>, string}>
     */
    public static function provideDocumentsWithAnEndpointOffTheWeb(): iterable
    {
        yield 'an assertion consumer service in plain http' => [
            'http://sp.example.org/saml/acs',
            [],
            'The Location of an md:AssertionConsumerService is not an https URL on a host name or an IP address, and the identity provider sends a browser there (spec/saml.md S-11).',
        ];
        yield 'a single logout service that runs a script' => [
            self::ASSERTION_CONSUMER,
            [new Endpoint(Binding::HttpRedirect, 'javascript:fetch(document.cookie)')],
            'The Location of an md:SingleLogoutService is not an https URL on a host name or an IP address, and the identity provider sends a browser there (spec/saml.md S-11).',
        ];
        yield 'a response location whose host carries a directive' => [
            self::ASSERTION_CONSUMER,
            [new Endpoint(Binding::HttpPost, 'https://sp.example.org/saml/slo', 'https://sp.example.org;sandbox/saml/slo')],
            'The ResponseLocation of an md:SingleLogoutService is not an https URL on a host name or an IP address, and the identity provider sends a browser there (spec/saml.md S-11).',
        ];
    }

    /**
     * S-11
     */
    #[Test]
    public function itReadsADocumentWhoseEndpointsAreHttpsOnAHost(): void
    {
        // Given
        $document = ServiceProviderDocuments::signed(
            new DateTimeImmutable('2026-10-01T00:00:00Z'),
            singleLogoutServices: [new Endpoint(Binding::HttpPost, 'https://[2001:db8::1]/saml/slo', 'https://sp.example.org:8443/saml/slo')],
            assertionConsumerService: 'HTTPS://sp.example.org:8443/saml/acs',
        );

        // When
        $metadata = $this->reader->readTrusted($document);

        // Then
        static::assertSame(ServiceProviderDocuments::SIGNED, $metadata->entityId);
    }

    /**
     * S-5
     */
    #[Test]
    public function itRefusesADocumentSignedByAnotherKey(): void
    {
        // Given
        $document = ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z'), 'idp');

        // Then
        $this->expectException(MetadataRefusedException::class);

        // When
        $this->reader->readSigned($document, [ServiceProviderDocuments::signer()]);
    }

    /**
     * S-5, M-2
     */
    #[Test]
    public function itRefusesAnUnsignedDocumentWhereASignerIsPinned(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The metadata carries no ds:Signature as the first child of its root (M-2).');

        // When
        $this->reader->readSigned(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'), [ServiceProviderDocuments::signer()]);
    }

    /**
     * S-6, model.md section 6.5 step 3
     */
    #[Test]
    public function itRefusesASignedDocumentWithoutValidUntil(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('Signed metadata carry a validUntil, without which an older document signed by the same key verifies as well (spec/saml.md S-6).');

        // When
        $this->reader->readSigned(ServiceProviderDocuments::signed(null), [ServiceProviderDocuments::signer()]);
    }

    #[Test]
    public function itRefusesToReadSignedMetadataUnderNoSigner(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('Signed metadata are verified under one certificate at least (spec/saml.md S-5).');

        // When
        $this->reader->readSigned(ServiceProviderDocuments::signed(new DateTimeImmutable('2026-10-01T00:00:00Z')), []);
    }

    /**
     * Section 6.3 step 1, S-10
     */
    #[Test]
    public function itReadsAnAcceptedDocumentOnceIntoBothReadings(): void
    {
        // When
        $read = $this->reader->readAccepted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertSame(
            [ServiceProviderDocuments::SIMPLESAMLPHP, ServiceProviderDocuments::SIMPLESAMLPHP, true, true],
            [$read->metadata->entityId, $read->role->entityId, $read->metadata->authnRequestsSigned, $read->role->authnRequestsSigned],
        );
    }

    /**
     * Section 6.3 step 1, S-6
     */
    #[Test]
    public function itSaysAnAcceptedDocumentReadBackWasNotReadSigned(): void
    {
        // When
        $read = $this->reader->readAccepted(ServiceProviderDocuments::simpleSamlPhp());

        // Then
        static::assertFalse($read->metadata->readSigned);
    }

    /**
     * Section 6.3 step 1
     */
    #[Test]
    public function itRefusesAnAcceptedDocumentPastItsValidity(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIsOrContains('(M-7)');

        // When
        $this->reader->readAccepted(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-09-01T00:00:00Z'));
    }

    /**
     * Section 6.3 step 1, S-11
     */
    #[Test]
    public function itRefusesAnAcceptedDocumentAnEndpointOfWhichIsNotHttpsOnAHost(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The Location of an md:AssertionConsumerService is not an https URL on a host name or an IP address, and the identity provider sends a browser there (spec/saml.md S-11).');

        // When
        $this->reader->readAccepted(ServiceProviderDocuments::signed(null, assertionConsumerService: 'http://sp.example.org/saml/acs'));
    }

    /**
     * S-5
     */
    #[Test]
    public function itRefusesAnAcceptedDocumentWithoutAServiceProviderRole(): void
    {
        // Then
        $this->expectException(MetadataRefusedException::class);
        $this->expectExceptionMessageIs('The metadata hold no service provider role of SAML 2.0 (spec/saml.md S-5).');

        // When
        $this->reader->readAccepted(ServiceProviderDocuments::identityProvider());
    }
}
