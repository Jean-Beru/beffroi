<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\Webauthn\WebauthnAttestation;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Beffroi\Core\Bridge\Webauthn\WebauthnPasskeyRegistrar;
use Beffroi\Core\Domain\Tenant\AttestationRoot;
use Beffroi\Core\Exception\PasskeyCeremonyFailedException;
use Beffroi\Core\Tests\Fixture\AttestationAuthority;
use Beffroi\Core\Tests\Fixture\AttestationCertificate;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use LogicException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use SpomkyLabs\Pki\ASN1\Type\Primitive\Integer;
use Symfony\Component\Clock\MockClock;
use Webauthn\AuthenticatorAttestationResponse;

/**
 * WebAuthn Level 3 §8.2.2
 */
final class WebauthnAttestationTest extends TestCase
{
    private AttestationAuthority $maker;

    protected function setUp(): void
    {
        $this->maker = AttestationAuthority::create();
    }

    #[Test]
    public function theSerialNumberIsTheOctetStringOfItsExtensionInHexadecimal(): void
    {
        // Given
        $attestation = $this->attestation($this->maker->attest("\xFF\x00\x7F"));

        // When / Then
        static::assertSame('ff007f', $attestation->serialNumber());
    }

    #[Test]
    public function aCertificateWithoutTheExtensionCarriesNoSerialNumber(): void
    {
        // Given
        $attestation = $this->attestation($this->maker->attest());

        // When / Then
        static::assertNull($attestation->serialNumber());
    }

    #[Test]
    public function aSerialNumberMarkedCriticalIsRefused(): void
    {
        // Given
        $attestation = $this->attestation($this->maker->attest("\x01", serialNumberIsCritical: true));

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIs('The attestation was refused: its serial number extension is marked critical (WebAuthn Level 3 §8.2.2).');

        // When
        $attestation->serialNumber();
    }

    #[Test]
    public function aSerialNumberThatIsNoOctetStringIsRefused(): void
    {
        // Given
        $attestation = $this->attestation($this->maker->attest(serialNumberValue: Integer::create(42)));

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIs('The attestation was refused: its serial number is no OCTET STRING (WebAuthn Level 3 §8.2.2).');

        // When
        $attestation->serialNumber();
    }

    #[Test]
    public function anEmptySerialNumberIsRefused(): void
    {
        // Given
        $attestation = $this->attestation($this->maker->attest(''));

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIs('The attestation was refused: its serial number names no authenticator (WebAuthn Level 3 §8.2.2).');

        // When
        $attestation->serialNumber();
    }

    #[Test]
    public function anAttestationChainsUpToNoneOfNoRoots(): void
    {
        // Given
        $attestation = $this->attestation($this->maker->attest());

        // When / Then
        static::assertFalse($attestation->chainsUpTo([]));
    }

    #[Test]
    public function anAttestationChainsUpToTheRootThatIssuedItsCertificate(): void
    {
        // Given
        $attestation = $this->attestation($this->maker->attest());

        // When / Then
        static::assertTrue($attestation->chainsUpTo([
            new AttestationRoot(AttestationAuthority::create('Another maker')->rootCertificate()),
            new AttestationRoot($this->maker->rootCertificate()),
        ]));
    }

    /**
     * The options of a tenant that asks for none: the ceremony then verifies everything but the metadata.
     */
    private function attestation(AttestationCertificate $certificate): WebauthnAttestation
    {
        $tenant = Fixtures::tenant();
        $ceremonies = Fixtures::ceremonies();
        $options = new WebauthnPasskeyRegistrar($ceremonies, new MockClock(Fixtures::now()))->creationOptions(
            Fixtures::user($tenant),
            Fixtures::userHandle(),
            [],
        );
        $device = new SoftwareAuthenticator('https://id.acme.example', attestation: 'packed', attestedBy: $certificate);
        $response = $ceremonies->credentialFromJson($device->create($ceremonies->optionsToJson($options)))->response;
        if (! $response instanceof AuthenticatorAttestationResponse) {
            throw new LogicException('The software authenticator answered no attestation.');
        }
        $record = $ceremonies->attestationValidator($tenant)->check($response, $options, WebauthnCeremonies::relyingPartyId($tenant));

        return $ceremonies->attestation($tenant, $response, $record, $options);
    }
}
