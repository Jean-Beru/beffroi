<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_map;
use Beffroi\Core\Domain\Credential\Attestation\AttestationEvidence;
use Beffroi\Core\Domain\Credential\Attestation\PasskeyAttestationRefusal;
use Beffroi\Core\Domain\Credential\Attestation\VerifiedRegistration;
use Beffroi\Core\Domain\Credential\PasskeyCredential;
use Beffroi\Core\Domain\Credential\PasskeyUserHandle;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\PasskeyAttestationRefusedException;
use Beffroi\Core\Exception\PasskeyCeremonyFailedException;
use Beffroi\Core\Port\PasskeyRegistrarInterface;
use function str_repeat;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

final class FakePasskeyRegistrar implements PasskeyRegistrarInterface
{
    /**
     * @var list<PublicKeyCredentialDescriptor>
     */
    public private(set) array $excluded = [];

    private ?CredentialRecord $record = null;

    private AttestationEvidence $evidence;

    private ?string $refusal = null;

    private ?PasskeyAttestationRefusal $policyRefusal = null;

    public function __construct()
    {
        $this->evidence = AttestationEvidence::declared();
    }

    public function returns(CredentialRecord $record, ?AttestationEvidence $evidence = null): void
    {
        $this->record = $record;
        $this->evidence = $evidence ?? AttestationEvidence::declared();
    }

    public function refuses(string $message): void
    {
        $this->refusal = $message;
    }

    public function refusesUnderThePolicy(PasskeyAttestationRefusal $refusal): void
    {
        $this->policyRefusal = $refusal;
    }

    /**
     * WebAuthn Level 3 §7.1, step 26
     */
    public static function record(
        PublicKeyCredentialCreationOptions $options,
        string $credentialId = 'credential-id',
        bool $backupEligible = false,
        bool $backedUp = false,
    ): CredentialRecord {
        return CredentialRecord::create(
            $credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            ['usb'],
            'none',
            EmptyTrustPath::create(),
            Uuid::v4(),
            'cose-public-key',
            $options->user->id,
            0,
            null,
            $backupEligible,
            $backedUp,
            false,
        );
    }

    public function creationOptions(User $user, PasskeyUserHandle $userHandle, array $existing): PublicKeyCredentialCreationOptions
    {
        $this->excluded = array_map(static fn (PasskeyCredential $passkey): PublicKeyCredentialDescriptor => $passkey
            ->record()
            ->getPublicKeyCredentialDescriptor(), $existing);

        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($user->tenant->name, 'id.acme.example'),
            PublicKeyCredentialUserEntity::create($user->username, $userHandle->value, $user->username),
            str_repeat('c', 32),
            [PublicKeyCredentialParameters::createPk(-7)],
            excludeCredentials: $this->excluded,
        );
    }

    public function verifyAttestation(Tenant $tenant, PublicKeyCredentialCreationOptions $options, string $response): VerifiedRegistration
    {
        if ($this->refusal !== null) {
            throw new PasskeyCeremonyFailedException($this->refusal);
        }
        if ($this->policyRefusal !== null) {
            throw new PasskeyAttestationRefusedException($this->policyRefusal, 'Refused by the policy of the tenant.');
        }

        return new VerifiedRegistration($this->record ?? self::record($options), $this->evidence);
    }
}
