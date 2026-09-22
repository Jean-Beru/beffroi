<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;
use Heidi\Core\Domain\Key\UnsealedKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\SigningKeyProviderInterface;

/**
 * Which key of the tenant signed, and which KMS opened it (architecture §3.3). The private material the
 * provider hands back stays where it is: what the panel keeps is the "kid" the JWS header will carry
 * anyway and the algorithm it is a key of.
 */
final readonly class ProfilingSigningKeyProvider implements SigningKeyProviderInterface
{
    public function __construct(
        private SigningKeyProviderInterface $keys,
        private OpProfile $profile,
        private KmsClient $kms,
    ) {
    }

    public function activeKey(Tenant $tenant, SignatureAlgorithmInterface $algorithm): UnsealedKey
    {
        $unsealed = $this->keys->activeKey($tenant, $algorithm);
        $this->profile->record(OpenedKey::observe($unsealed, 'signs', $this->kms));

        return $unsealed;
    }
}
