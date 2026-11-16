<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\Webauthn\WiredPasskeyAttestationPolicies;
use Beffroi\Core\Domain\Credential\Attestation\DirectAttestation;
use Beffroi\Core\Domain\Credential\Attestation\NoAttestation;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0046
 */
final class WiredPasskeyAttestationPoliciesTest extends TestCase
{
    #[Test]
    public function aPolicyIsFoundByTheNameItGivesItself(): void
    {
        // Given
        $policies = new WiredPasskeyAttestationPolicies([new NoAttestation(), new DirectAttestation()]);

        // When / Then
        static::assertInstanceOf(DirectAttestation::class, $policies->named('direct'));
    }

    #[Test]
    public function aNameNoWiredPolicyCarriesIsRefusedNamingTheWiredOnes(): void
    {
        // Given
        $policies = new WiredPasskeyAttestationPolicies([new NoAttestation(), new DirectAttestation()]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('This provider wires no passkey attestation policy "indirect"; it wires none, direct.');

        // When
        $policies->named('indirect');
    }

    #[Test]
    public function aPolicyIsWiredOnce(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new WiredPasskeyAttestationPolicies([new NoAttestation(), new NoAttestation()]);
    }
}
