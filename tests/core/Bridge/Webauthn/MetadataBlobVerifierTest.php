<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\Webauthn\MetadataBlobVerifier;
use Beffroi\Core\Exception\MetadataBlobRefusedException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use Beffroi\Core\Tests\Fixture\MetadataSigner;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_replace;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;

/**
 * FIDO Metadata Service v3 §3.1.7 and §3.2: a blob is a JWS whose chain leads to the root the relying
 * party pins; anything short of that is refused, whatever it claims.
 */
final class MetadataBlobVerifierTest extends TestCase
{
    private const string AAGUID = '2fc0579f-8113-47ea-b116-bb5a8db9202a';

    private MetadataSigner $service;

    private MetadataBlobVerifier $verifier;

    protected function setUp(): void
    {
        $this->service = MetadataSigner::create();
        $this->verifier = new MetadataBlobVerifier(PhpCertificateChainValidator::create(new MockHttpClient(), new MockClock(Fixtures::now())));
    }

    #[Test]
    public function aBlobSignedUnderThePinnedRootIsVerifiedAndRead(): void
    {
        // Given
        $payload = MetadataBlobs::payload(
            [MetadataBlobs::entry(self::AAGUID, [AuthenticatorStatus::FIDO_CERTIFIED])],
            serialNumber: 42,
            nextUpdate: '2026-10-01',
        );
        $token = $this->service->sign($payload);

        // When
        $blob = $this->verifier->verify($token, $this->service->rootCertificate());

        // Then
        static::assertSame($payload, $blob->payload);
        static::assertSame(42, $blob->content->no);
        static::assertSame('2026-10-01', $blob->content->nextUpdate);
        static::assertCount(1, $blob->content->entries);
        static::assertSame(self::AAGUID, $blob->content->entries[0]->aaguid);
        static::assertSame(AuthenticatorStatus::FIDO_CERTIFIED, $blob->content->entries[0]->statusReports[0]->status);
    }

    #[Test]
    public function aBlobSignedUnderAnotherRootIsRefused(): void
    {
        // Given
        $other = MetadataSigner::create('Another Service');
        $token = $other->sign(MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]));

        // Then
        $this->expectException(MetadataBlobRefusedException::class);
        $this->expectExceptionMessageIsOrContains('The certificate chain of the blob does not lead to the pinned root');

        // When
        $this->verifier->verify($token, $this->service->rootCertificate());
    }

    /**
     * A chain that leads to the root but is not the signer's: the signature is checked with the key of the
     * certificate named, and does not hold.
     */
    #[Test]
    public function aBlobWhoseSignatureDoesNotHoldUnderTheCertificateNamedIsRefused(): void
    {
        // Given
        $other = MetadataSigner::create('Another Service');
        $token = $other->sign(MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]), $this->service->chain());

        // Then
        $this->expectException(MetadataBlobRefusedException::class);
        $this->expectExceptionMessageIs('The signature of the blob does not hold under the certificate it names.');

        // When
        $this->verifier->verify($token, $this->service->rootCertificate());
    }

    #[Test]
    public function aBlobWhosePayloadWasAlteredIsRefused(): void
    {
        // Given
        $token = $this->service->sign(MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]));
        [$header, $payload, $signature] = explode('.', $token);
        $altered = $header . '.' . str_replace('A', 'B', $payload) . '.' . $signature;

        // Then
        $this->expectException(MetadataBlobRefusedException::class);
        $this->expectExceptionMessageIs('The signature of the blob does not hold under the certificate it names.');

        // When
        $this->verifier->verify($altered, $this->service->rootCertificate());
    }

    #[Test]
    public function aBlobWithoutCertificateChainIsRefused(): void
    {
        // Given
        $token = $this->service->sign(MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]), []);

        // Then
        $this->expectException(MetadataBlobRefusedException::class);
        $this->expectExceptionMessageIs('The protected header of the blob names no certificate chain ("x5c").');

        // When
        $this->verifier->verify($token, $this->service->rootCertificate());
    }

    #[Test]
    public function aBlobWhoseChainIsNotAListOfCertificatesIsRefused(): void
    {
        // Given
        $token = $this->service->sign(MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]), [$this->service->chain()[0], '']);

        // Then
        $this->expectException(MetadataBlobRefusedException::class);
        $this->expectExceptionMessageIs('The certificate chain of the blob is not a list of certificates.');

        // When
        $this->verifier->verify($token, $this->service->rootCertificate());
    }

    /**
     * The chain is checked whole: the signer alone, without the intermediate that leads to the root, is
     * not enough.
     */
    #[Test]
    public function aBlobWhoseChainLacksTheIntermediateIsRefused(): void
    {
        // Given
        $token = $this->service->sign(MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]), [$this->service->chain()[0]]);

        // Then
        $this->expectException(MetadataBlobRefusedException::class);
        $this->expectExceptionMessageIsOrContains('The certificate chain of the blob does not lead to the pinned root');

        // When
        $this->verifier->verify($token, $this->service->rootCertificate());
    }

    #[Test]
    public function whatIsNotACompactJwsIsRefused(): void
    {
        // Then
        $this->expectException(MetadataBlobRefusedException::class);
        $this->expectExceptionMessageIsOrContains('The blob is not a compact JWS');

        // When
        $this->verifier->verify('<html>Not Found</html>', $this->service->rootCertificate());
    }

    #[Test]
    public function aSignedPayloadThatIsNotABlobIsRefused(): void
    {
        // Given
        $token = $this->service->sign('{"entries":"none"}');

        // Then
        $this->expectException(MetadataBlobRefusedException::class);
        $this->expectExceptionMessageIsOrContains('The payload of the blob is not a Metadata BLOB payload');

        // When
        $this->verifier->verify($token, $this->service->rootCertificate());
    }
}
