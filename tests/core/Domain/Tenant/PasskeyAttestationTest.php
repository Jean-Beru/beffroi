<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Tenant;

use Beffroi\Core\Domain\Credential\Attestation\DirectAttestation;
use Beffroi\Core\Domain\Credential\Attestation\EnterpriseAttestation;
use Beffroi\Core\Domain\Credential\Attestation\NoAttestation;
use Beffroi\Core\Domain\Tenant\AdmittedModelUnderAlert;
use Beffroi\Core\Domain\Tenant\AttestationRoot;
use Beffroi\Core\Domain\Tenant\PasskeyAttestation;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\AttestationAuthority;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0046
 */
final class PasskeyAttestationTest extends TestCase
{
    private const string AAGUID = 'cb69481e-8ff7-4039-93ec-0a2729a154a8';

    #[Test]
    public function aTenantAsksForNoAttestationByDefault(): void
    {
        // When / Then
        static::assertSame('none', PasskeyAttestation::none()->policy->name());
    }

    /**
     * @param list<AttestationRoot> $roots
     * @param list<AttestationRoot> $ownRoots
     * @param list<AdmittedModelUnderAlert> $modelsUnderAlert
     */
    #[Test]
    #[DataProvider('provideWhatNoneDoesNotRead')]
    public function noneReadsNothingElse(array $roots, array $ownRoots, array $modelsUnderAlert, string $refusal): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($refusal);

        // When
        new PasskeyAttestation(new NoAttestation(), $roots, $ownRoots, $modelsUnderAlert);
    }

    /**
     * @return iterable<string, array{list<AttestationRoot>, list<AttestationRoot>, list<AdmittedModelUnderAlert>, string}>
     */
    public static function provideWhatNoneDoesNotRead(): iterable
    {
        $roots = 'The passkey attestation policy "none" verifies no chain: only "enterprise" reads roots of attestations.';
        yield 'a root' => [[self::root()], [], [], $roots];
        yield 'an own root' => [[], [self::root()], [], $roots];
        yield 'a model under alert' => [
            [],
            [],
            [AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31')],
            'The passkey attestation policy "none" proves no model, so it refuses none under a security alert and admits none either.',
        ];
    }

    #[Test]
    public function directReadsNoRootOfTheTenant(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The passkey attestation policy "direct" verifies a chain up to the roots the FIDO metadata name: only "enterprise" reads roots of the tenant.');

        // When
        new PasskeyAttestation(new DirectAttestation(), [self::root()]);
    }

    #[Test]
    public function enterpriseThatPinsNoRootIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The passkey attestation policy "enterprise" admits the attestations of the roots the tenant pins, and it pins none.');

        // When
        new PasskeyAttestation(new EnterpriseAttestation());
    }

    #[Test]
    public function enterpriseMayPinItsOwnAuthoritiesAlone(): void
    {
        // When
        $attestation = new PasskeyAttestation(new EnterpriseAttestation(), ownRoots: [self::root()]);

        // Then
        static::assertCount(1, $attestation->ownRoots);
    }

    #[Test]
    public function aModelIsAdmittedUnderItsAlertOnceAtMost(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The model "cb69481e-8ff7-4039-93ec-0a2729a154a8" is admitted under its security alert twice.');

        // When
        new PasskeyAttestation(new DirectAttestation(), modelsUnderAlert: [
            AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31'),
            AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-06-30'),
        ]);
    }

    #[Test]
    public function twoAttestationsOfTheSameChoicesAreEqual(): void
    {
        // Given
        $root = self::root();
        $first = new PasskeyAttestation(
            new EnterpriseAttestation(),
            [$root],
            modelsUnderAlert: [AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31')],
        );
        $second = new PasskeyAttestation(
            new EnterpriseAttestation(),
            [$root],
            modelsUnderAlert: [AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31')],
        );

        // When / Then
        static::assertTrue($first->equals($second));
    }

    #[Test]
    #[DataProvider('provideOtherChoices')]
    public function anotherChoiceIsAnotherAttestation(PasskeyAttestation $other): void
    {
        // Given
        $attestation = new PasskeyAttestation(new DirectAttestation(), modelsUnderAlert: [AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31')]);

        // When / Then
        static::assertFalse($attestation->equals($other));
    }

    /**
     * @return iterable<string, array{PasskeyAttestation}>
     */
    public static function provideOtherChoices(): iterable
    {
        yield 'another policy' => [new PasskeyAttestation(
            new EnterpriseAttestation(),
            [self::root()],
            modelsUnderAlert: [AdmittedModelUnderAlert::fromStrings(self::AAGUID, '2027-03-31')],
        )];
        yield 'another day' => [new PasskeyAttestation(new DirectAttestation(), modelsUnderAlert: [AdmittedModelUnderAlert::fromStrings(
            self::AAGUID,
            '2027-04-01',
        )])];
        yield 'no model' => [new PasskeyAttestation(new DirectAttestation())];
    }

    #[Test]
    public function anotherRootIsAnotherAttestation(): void
    {
        // Given
        $attestation = new PasskeyAttestation(new EnterpriseAttestation(), [self::root()]);

        // When / Then
        static::assertFalse($attestation->equals(new PasskeyAttestation(new EnterpriseAttestation(), [self::root()])));
    }

    #[Test]
    public function aRootIsNoOwnRoot(): void
    {
        // Given
        $root = self::root();

        // When / Then
        static::assertFalse(new PasskeyAttestation(new EnterpriseAttestation(), [$root])->equals(
            new PasskeyAttestation(new EnterpriseAttestation(), ownRoots: [$root]),
        ));
    }

    private static function root(): AttestationRoot
    {
        return new AttestationRoot(AttestationAuthority::create()->rootCertificate());
    }
}
