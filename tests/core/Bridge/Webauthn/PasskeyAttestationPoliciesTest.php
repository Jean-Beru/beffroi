<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryMetadataBlobStore;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Beffroi\Core\Bridge\Webauthn\WebauthnPasskeyRegistrar;
use Beffroi\Core\Domain\Credential\Attestation\AttestationEvidence;
use Beffroi\Core\Domain\Credential\Attestation\DirectAttestation;
use Beffroi\Core\Domain\Credential\Attestation\EnterpriseAttestation;
use Beffroi\Core\Domain\Credential\Attestation\PasskeyAttestationRefusal;
use Beffroi\Core\Domain\Tenant\AdmittedModelUnderAlert;
use Beffroi\Core\Domain\Tenant\AttestationRoot;
use Beffroi\Core\Domain\Tenant\PasskeyAttestation;
use Beffroi\Core\Exception\PasskeyAttestationRefusedException;
use Beffroi\Core\Exception\PasskeyCeremonyFailedException;
use Beffroi\Core\Tests\Fixture\AttestationAuthority;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use Beffroi\Core\Tests\Fixture\SoftwareAuthenticator;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function random_bytes;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;

/**
 * WebAuthn Level 3 §5.4.7, §7.1 steps 19 to 22, Decision 0046
 */
final class PasskeyAttestationPoliciesTest extends TestCase
{
    private const string ORIGIN = 'https://id.acme.example';

    private AttestationAuthority $maker;

    private string $aaguid;

    private InMemoryMetadataBlobStore $metadata;

    protected function setUp(): void
    {
        $this->maker = AttestationAuthority::create('Maker of the tests');
        $this->aaguid = random_bytes(16);
        $this->metadata = new InMemoryMetadataBlobStore();
    }

    /**
     * §5.4.7
     */
    #[Test]
    #[DataProvider('providePolicies')]
    public function theOptionsAskWhatThePolicyOfTheTenantAsks(PasskeyAttestation $policy, string $asked): void
    {
        // Given
        $tenant = Fixtures::tenant(passkeyAttestation: $policy);

        // When
        $options = $this->registrar()->creationOptions(Fixtures::user($tenant), Fixtures::userHandle(), []);

        // Then
        static::assertSame($asked, $options->attestation);
    }

    /**
     * @return iterable<string, array{PasskeyAttestation, string}>
     */
    public static function providePolicies(): iterable
    {
        yield 'none' => [PasskeyAttestation::none(), 'none'];
        yield 'direct' => [new PasskeyAttestation(new DirectAttestation()), 'direct'];
        yield 'enterprise' => [new PasskeyAttestation(new EnterpriseAttestation(), [new AttestationRoot(
                AttestationAuthority::create()->rootCertificate(),
            )]), 'enterprise'];
    }

    #[Test]
    public function underNoneAnAttestationTheMetadataWouldVerifyLeavesTheModelDeclared(): void
    {
        // Given
        $this->theMetadataKnowTheModel();

        // When
        $evidence = $this->enrol(PasskeyAttestation::none(), $this->attested());

        // Then
        static::assertEquals(AttestationEvidence::declared(), $evidence);
    }

    /**
     * §7.1 step 22, FIDO Metadata Service v3.1.1 §3.1.3
     */
    #[Test]
    public function underDirectAnAttestationThatChainsUpToTheRootsTheMetadataNameVerifiesTheModel(): void
    {
        // Given
        $this->theMetadataKnowTheModel();

        // When
        $evidence = $this->enrol(new PasskeyAttestation(new DirectAttestation()), $this->attested());

        // Then
        static::assertEquals(AttestationEvidence::verified(), $evidence);
    }

    /**
     * §5.4.7, §6
     */
    #[Test]
    #[DataProvider('provideAuthenticatorsWhoseModelIsOnlyDeclared')]
    public function underDirectAPasskeyIsEnrolledWithItsModelDeclaredWhenNothingProvesIt(string $attestation, bool $attested, bool $known): void
    {
        // Given
        if ($known) {
            $this->theMetadataKnowTheModel();
        }
        $device = new SoftwareAuthenticator(
            self::ORIGIN,
            attestation: $attestation,
            aaguid: $this->aaguid,
            attestedBy: $attested ? $this->maker->attest() : null,
        );

        // When
        $evidence = $this->enrol(new PasskeyAttestation(new DirectAttestation()), $device);

        // Then
        static::assertEquals(AttestationEvidence::declared(), $evidence);
    }

    /**
     * @return iterable<string, array{string, bool, bool}>
     */
    public static function provideAuthenticatorsWhoseModelIsOnlyDeclared(): iterable
    {
        yield 'an attestation of a model the metadata do not know' => ['packed', true, false];
        yield 'no attestation, the client having removed it' => ['none', false, true];
        yield 'a self attestation' => ['packed', false, true];
    }

    /**
     * §7.1 step 22
     */
    #[Test]
    public function underDirectAnAttestationThatDoesNotChainUpToTheRootsTheMetadataNameIsRefused(): void
    {
        // Given
        $this->theMetadataKnowTheModel();
        $device = new SoftwareAuthenticator(
            self::ORIGIN,
            attestation: 'packed',
            aaguid: $this->aaguid,
            attestedBy: AttestationAuthority::create('Another maker')->attest(),
        );

        // Then
        $this->expectException(PasskeyCeremonyFailedException::class);
        $this->expectExceptionMessageIsOrContains('The attestation was refused');

        // When
        $this->enrol(new PasskeyAttestation(new DirectAttestation()), $device);
    }

    /**
     * FIDO Metadata Service v3.1.1 §3.1.4.2
     */
    #[Test]
    #[DataProvider('provideSecurityNotifications')]
    public function underDirectAModelWhoseLastStatusReportIsASecurityNotificationIsRefused(string $status): void
    {
        // Given
        $this->theMetadataKnowTheModel([AuthenticatorStatus::FIDO_CERTIFIED, $status]);

        // When
        try {
            $this->enrol(new PasskeyAttestation(new DirectAttestation()), $this->attested());
            static::fail('The passkey was enrolled.');
        } catch (PasskeyAttestationRefusedException $exception) {
            // Then
            static::assertSame(PasskeyAttestationRefusal::ModelUnderSecurityAlert, $exception->refusal);
        }
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideSecurityNotifications(): iterable
    {
        yield 'user verification bypass' => [AuthenticatorStatus::USER_VERIFICATION_BYPASS];
        yield 'attestation key compromise' => [AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE];
        yield 'user key remote compromise' => [AuthenticatorStatus::USER_KEY_REMOTE_COMPROMISE];
        yield 'user key physical compromise' => [AuthenticatorStatus::USER_KEY_PHYSICAL_COMPROMISE];
    }

    /**
     * FIDO Metadata Service v3.1.1 §3.1.3
     */
    #[Test]
    public function aModelWhoseLastStatusReportIsNoSecurityNotificationIsEnrolledWhateverCameBefore(): void
    {
        // Given
        $this->theMetadataKnowTheModel([AuthenticatorStatus::USER_VERIFICATION_BYPASS, AuthenticatorStatus::UPDATE_AVAILABLE]);

        // When
        $evidence = $this->enrol(new PasskeyAttestation(new DirectAttestation()), $this->attested());

        // Then
        static::assertEquals(AttestationEvidence::verified(), $evidence);
    }

    /**
     * Decision 0006
     */
    #[Test]
    #[DataProvider('provideDaysTheAdmissionCovers')]
    public function aModelUnderAnAlertTheTenantAdmitsIsEnrolledAndMarkedUntilItsDay(string $now): void
    {
        // Given
        $this->theMetadataKnowTheModel([AuthenticatorStatus::USER_VERIFICATION_BYPASS]);
        $policy = new PasskeyAttestation(new DirectAttestation(), modelsUnderAlert: [
            AdmittedModelUnderAlert::fromStrings(Uuid::fromBinary($this->aaguid)->toRfc4122(), '2026-09-30'),
        ]);

        // When
        $evidence = $this->enrol($policy, $this->attested(), new DateTimeImmutable($now));

        // Then
        static::assertEquals(AttestationEvidence::verified(underSecurityAlert: true), $evidence);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDaysTheAdmissionCovers(): iterable
    {
        yield 'before its day' => ['2026-09-15T10:00:00+00:00'];
        yield 'on its last second' => ['2026-09-30T23:59:59+00:00'];
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function theRefusalOfAModelUnderAlertReturnsAfterTheDayTheTenantNamed(): void
    {
        // Given
        $this->theMetadataKnowTheModel([AuthenticatorStatus::USER_VERIFICATION_BYPASS]);
        $policy = new PasskeyAttestation(new DirectAttestation(), modelsUnderAlert: [
            AdmittedModelUnderAlert::fromStrings(Uuid::fromBinary($this->aaguid)->toRfc4122(), '2026-09-30'),
        ]);

        // Then
        $this->expectException(PasskeyAttestationRefusedException::class);

        // When
        $this->enrol($policy, $this->attested(), new DateTimeImmutable('2026-10-01T00:00:00+00:00'));
    }

    /**
     * §5.4.7, §8.2.2
     */
    #[Test]
    public function underEnterpriseAnAttestationOfAPinnedRootCarryingASerialNumberIsEnrolledWithIt(): void
    {
        // When
        $evidence = $this->enrol($this->enterprise(roots: [$this->maker]), $this->attested("\x0A\x1B\x2C\x3D"));

        // Then
        static::assertEquals(AttestationEvidence::enterprise('0a1b2c3d'), $evidence);
    }

    /**
     * §8.2.2
     */
    #[Test]
    public function underEnterpriseAnAttestationOfAPinnedRootWithoutASerialNumberIsRefused(): void
    {
        // When
        try {
            $this->enrol($this->enterprise(roots: [$this->maker]), $this->attested());
            static::fail('The passkey was enrolled.');
        } catch (PasskeyAttestationRefusedException $exception) {
            // Then
            static::assertSame(PasskeyAttestationRefusal::OrganisationKeysOnly, $exception->refusal);
        }
    }

    #[Test]
    public function underEnterpriseAnAttestationOfAnAuthorityOfTheTenantNeedsNoSerialNumber(): void
    {
        // When
        $evidence = $this->enrol($this->enterprise(ownRoots: [$this->maker]), $this->attested());

        // Then
        static::assertEquals(AttestationEvidence::enterprise(null), $evidence);
    }

    #[Test]
    #[DataProvider('provideAuthenticatorsTheOrganisationDidNotAttest')]
    public function underEnterpriseAPasskeyNoPinnedRootAttestsIsRefused(string $attestation, bool $attestedByAnotherMaker): void
    {
        // Given
        $device = new SoftwareAuthenticator(
            self::ORIGIN,
            attestation: $attestation,
            aaguid: $this->aaguid,
            attestedBy: $attestedByAnotherMaker ? AttestationAuthority::create('Another maker')->attest("\x01") : null,
        );

        // When
        try {
            $this->enrol($this->enterprise(roots: [$this->maker]), $device);
            static::fail('The passkey was enrolled.');
        } catch (PasskeyAttestationRefusedException $exception) {
            // Then
            static::assertSame(PasskeyAttestationRefusal::OrganisationKeysOnly, $exception->refusal);
        }
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideAuthenticatorsTheOrganisationDidNotAttest(): iterable
    {
        yield 'an attestation of another authority' => ['packed', true];
        yield 'no attestation' => ['none', false];
        yield 'a self attestation' => ['packed', false];
    }

    /**
     * FIDO Metadata Service v3.1.1 §3.1.4.2
     */
    #[Test]
    public function underEnterpriseAModelUnderASecurityAlertIsRefused(): void
    {
        // Given
        $this->theMetadataKnowTheModel([AuthenticatorStatus::ATTESTATION_KEY_COMPROMISE]);

        // When
        try {
            $this->enrol($this->enterprise(roots: [$this->maker]), $this->attested("\x01"));
            static::fail('The passkey was enrolled.');
        } catch (PasskeyAttestationRefusedException $exception) {
            // Then
            static::assertSame(PasskeyAttestationRefusal::ModelUnderSecurityAlert, $exception->refusal);
        }
    }

    /**
     * @param list<string> $statuses
     */
    private function theMetadataKnowTheModel(array $statuses = [AuthenticatorStatus::FIDO_CERTIFIED]): void
    {
        $this->metadata->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(
            Uuid::fromBinary($this->aaguid)->toRfc4122(),
            $statuses,
            attestationRootCertificates: [$this->maker->rootInMetadata()],
        )]));
    }

    private function attested(?string $serialNumber = null): SoftwareAuthenticator
    {
        return new SoftwareAuthenticator(self::ORIGIN, attestation: 'packed', aaguid: $this->aaguid, attestedBy: $this->maker->attest($serialNumber));
    }

    /**
     * @param list<AttestationAuthority> $roots
     * @param list<AttestationAuthority> $ownRoots
     */
    private function enterprise(array $roots = [], array $ownRoots = []): PasskeyAttestation
    {
        $pinned = static fn (AttestationAuthority $authority): AttestationRoot => new AttestationRoot($authority->rootCertificate());

        return new PasskeyAttestation(new EnterpriseAttestation(), array_map($pinned, $roots), array_map($pinned, $ownRoots));
    }

    private function enrol(PasskeyAttestation $policy, SoftwareAuthenticator $device, ?DateTimeImmutable $now = null): AttestationEvidence
    {
        $tenant = Fixtures::tenant(passkeyAttestation: $policy);
        $ceremonies = Fixtures::ceremonies($this->metadata);
        $registrar = $this->registrar($ceremonies, $now);
        $options = $registrar->creationOptions(Fixtures::user($tenant), Fixtures::userHandle(), []);

        return $registrar->verifyAttestation($tenant, $options, $device->create($ceremonies->optionsToJson($options)))->evidence;
    }

    private function registrar(?WebauthnCeremonies $ceremonies = null, ?DateTimeImmutable $now = null): WebauthnPasskeyRegistrar
    {
        return new WebauthnPasskeyRegistrar($ceremonies ?? Fixtures::ceremonies($this->metadata), new MockClock($now ?? Fixtures::now()));
    }
}
