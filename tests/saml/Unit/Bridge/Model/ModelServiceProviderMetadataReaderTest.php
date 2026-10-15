<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Model\ModelServiceProviderMetadataReader;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Tests\Fixture\ServiceProviderDocuments;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use function substr;

/**
 * spec/saml.md S-5, S-6, section 6.2 steps 3 and 4: the metadata of a service provider read by saml2-model's
 * MetadataReader, by the channel or under the signers a declaration pins, at 2026-09-15T10:00:00Z.
 */
final class ModelServiceProviderMetadataReaderTest extends TestCase
{
    private ModelServiceProviderMetadataReader $reader;

    protected function setUp(): void
    {
        $this->reader = new ModelServiceProviderMetadataReader(new MockClock(Fixtures::now()));
    }

    /**
     * The acceptance of issue #729: the metadata a SimpleSAMLphp 2.5.3.1 service provider publishes, read by the
     * channel, its entity ID and its key for encryption.
     */
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
     * S-9, section 6.2 step 3: the SimpleSAMLphp service provider says it signs its requests.
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
     * S-9, section 6.2 step 3, Metadata §2.4.4: a document without AuthnRequestsSigned, as Entra's is written, says
     * nothing of a signature.
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

    #[Test]
    public function itReadsTheValidUntilOfADocument(): void
    {
        // When
        $metadata = $this->reader->readTrusted(ServiceProviderDocuments::simpleSamlPhpValidUntil('2026-10-01T00:00:00Z'));

        // Then
        static::assertEquals(new DateTimeImmutable('2026-10-01T00:00:00Z'), $metadata->validUntil);
    }

    /**
     * S-6, the acceptance of issue #729: an expired document is refused (M-7), the skew of the model past.
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
     * Section 5.1: a certificate the model reads and that is not the canonical base64 of its DER, one whose unused bits
     * are set, is refused rather than kept in another spelling than the one it is compared in.
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
     * S-5: a document without a service provider role is no service provider's.
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
     * Section 6.2 step 3: what Core refuses is refused, with its message.
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
     * S-5: a document signed by a key the declaration pins is read under it.
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
     * S-5: a document signed by another key than the pinned ones is refused.
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
     * S-5, M-2: an unsigned document is refused where a signer is pinned.
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
     * S-6: a signed document without validUntil is bounded by nothing, and an older one signed by the same key would
     * verify as well (model.md section 6.5 step 3).
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
}
