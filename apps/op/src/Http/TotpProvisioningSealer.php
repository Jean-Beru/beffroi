<?php

declare(strict_types=1);

namespace App\Http;

use function base64_decode;
use function base64_encode;
use Beffroi\Core\Domain\Credential\TotpProvisioning;
use Beffroi\Core\Domain\Credential\TotpSecret;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\SecretSealerInterface;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;

/**
 * A whole provisioning under the seal of the tenant's KMS (SecretSealerInterface, architecture §3.3):
 * the secret, the URI that carries it in base32 and the backup codes, as one JSON document the envelope
 * authenticates, so that what a session store keeps of an enrolment in progress is opaque.
 */
final readonly class TotpProvisioningSealer
{
    public function __construct(
        private SecretSealerInterface $sealer,
    ) {
    }

    /**
     * @throws KmsUnavailableException when the KMS of the tenant does not answer or refuses to seal
     * @throws RuntimeException when the envelope cannot be made for another reason
     */
    public function seal(User $user, TotpProvisioning $provisioning): string
    {
        return $this->sealer->seal($user->tenant, json_encode([
            'secret' => base64_encode($provisioning->secret->bytes),
            'uri' => $provisioning->uri,
            'backup_codes' => $provisioning->backupCodes,
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * @throws KmsUnavailableException when the KMS of the tenant does not answer or refuses to open
     * @throws RuntimeException when the envelope was not sealed for this tenant
     * @throws InvalidArgumentException when what the envelope holds is not a provisioning
     */
    public function unseal(User $user, string $sealed): TotpProvisioning
    {
        $document = json_decode($this->sealer->unseal($user->tenant, $sealed), true, 3, JSON_THROW_ON_ERROR);
        $secret = is_array($document) ? $document['secret'] ?? null : null;
        $uri = is_array($document) ? $document['uri'] ?? null : null;
        $backupCodes = is_array($document) ? $document['backup_codes'] ?? null : null;
        if (! is_string($secret) || ! is_string($uri) || ! is_array($backupCodes)) {
            throw new InvalidArgumentException('The envelope holds no provisioning.');
        }
        $codes = [];
        foreach ($backupCodes as $code) {
            if (! is_string($code)) {
                throw new InvalidArgumentException('The envelope holds no provisioning.');
            }
            $codes[] = $code;
        }
        $bytes = base64_decode($secret, true);
        if ($bytes === false) {
            throw new InvalidArgumentException('The envelope holds no provisioning.');
        }

        return new TotpProvisioning(new TotpSecret($bytes), $uri, $codes);
    }
}
