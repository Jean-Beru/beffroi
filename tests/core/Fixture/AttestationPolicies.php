<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Application\Passkey\PasskeyAttestations;
use Beffroi\Core\Bridge\Webauthn\PkiAttestationRootReader;
use Beffroi\Core\Bridge\Webauthn\WiredPasskeyAttestationPolicies;
use Beffroi\Core\Domain\Credential\Attestation\DirectAttestation;
use Beffroi\Core\Domain\Credential\Attestation\EnterpriseAttestation;
use Beffroi\Core\Domain\Credential\Attestation\NoAttestation;

/**
 * Decision 0046
 */
final readonly class AttestationPolicies
{
    public static function wired(): PasskeyAttestations
    {
        return new PasskeyAttestations(
            new WiredPasskeyAttestationPolicies([new NoAttestation(), new DirectAttestation(), new EnterpriseAttestation()]),
            new PkiAttestationRootReader(),
        );
    }
}
