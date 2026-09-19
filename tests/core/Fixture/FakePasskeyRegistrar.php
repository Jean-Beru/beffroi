<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use function array_map;
use Heidi\Core\Domain\Credential\PasskeyCredential;
use Heidi\Core\Domain\Credential\PasskeyUserHandle;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Exception\PasskeyCeremonyFailedException;
use Heidi\Core\Port\PasskeyRegistrarInterface;
use function str_repeat;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * A registration ceremony that trusts the test: the options carry what the core gave, the record comes
 * back as prepared, or the ceremony fails as told.
 */
final class FakePasskeyRegistrar implements PasskeyRegistrarInterface
{
    /**
     * @var list<PublicKeyCredentialDescriptor>
     */
    public private(set) array $excluded = [];

    private ?CredentialRecord $record = null;

    private ?string $refusal = null;

    public function returns(CredentialRecord $record): void
    {
        $this->record = $record;
    }

    public function refuses(string $message): void
    {
        $this->refusal = $message;
    }

    /**
     * A record as the ceremony builds it (WebAuthn Level 3 §7.1, step 26), the handle of the options.
     */
    public static function record(PublicKeyCredentialCreationOptions $options, string $credentialId = 'credential-id', bool $backupEligible = false, bool $backedUp = false): CredentialRecord
    {
        return CredentialRecord::create($credentialId, PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, ['usb'], 'none', EmptyTrustPath::create(), Uuid::v4(), 'cose-public-key', $options->user->id, 0, null, $backupEligible, $backedUp, false);
    }

    public function creationOptions(User $user, PasskeyUserHandle $userHandle, array $existing): PublicKeyCredentialCreationOptions
    {
        $this->excluded = array_map(static fn (PasskeyCredential $passkey): PublicKeyCredentialDescriptor => $passkey->record()->getPublicKeyCredentialDescriptor(), $existing);

        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create($user->tenant->name, 'id.acme.example'),
            PublicKeyCredentialUserEntity::create($user->username, $userHandle->value, $user->username),
            str_repeat('c', 32),
            [PublicKeyCredentialParameters::createPk(-7)],
            excludeCredentials: $this->excluded,
        );
    }

    public function verifyAttestation(PublicKeyCredentialCreationOptions $options, string $response): CredentialRecord
    {
        if ($this->refusal !== null) {
            throw new PasskeyCeremonyFailedException($this->refusal);
        }

        return $this->record ?? self::record($options);
    }
}
