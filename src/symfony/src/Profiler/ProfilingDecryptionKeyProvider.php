<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler;

use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\DecryptionKeyProviderInterface;

/**
 * Which key of the tenant opened a JWE a client encrypted to the provider, and which KMS opened that key
 * in turn. What the panel keeps is the "kid" the JOSE header of the JWE already named.
 */
final readonly class ProfilingDecryptionKeyProvider implements DecryptionKeyProviderInterface
{
    public function __construct(
        private DecryptionKeyProviderInterface $keys,
        private OpProfile $profile,
        private KmsClient $kms,
    ) {
    }

    public function decryptionKey(Tenant $tenant, string $kid): UnsealedKey
    {
        $unsealed = $this->keys->decryptionKey($tenant, $kid);
        $this->profile->record(OpenedKey::observe($unsealed, 'opens an envelope a client sealed', $this->kms));

        return $unsealed;
    }
}
