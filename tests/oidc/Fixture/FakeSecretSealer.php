<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\RuntimeException;
use Heidi\Core\Port\SecretSealerInterface;
use SensitiveParameter;
use function sprintf;
use function str_starts_with;
use function strlen;
use function substr;

/**
 * A sealer that seals nothing: it writes the tenant into the envelope and reads it back, so that a test
 * sees what would have been kept and that an envelope of one tenant does not open for another, which is
 * what the KMS of a deployment guarantees (architecture §3.3).
 */
final readonly class FakeSecretSealer implements SecretSealerInterface
{
    public function seal(Tenant $tenant, #[SensitiveParameter] string $secret): string
    {
        return self::prefix($tenant) . $secret;
    }

    public function unseal(Tenant $tenant, #[SensitiveParameter] string $sealed): string
    {
        $prefix = self::prefix($tenant);
        if (! str_starts_with($sealed, $prefix)) {
            throw new RuntimeException(sprintf('The envelope was not sealed for the tenant "%s".', $tenant->slug));
        }

        return substr($sealed, strlen($prefix));
    }

    private static function prefix(Tenant $tenant): string
    {
        return sprintf('sealed:%s:', $tenant->slug);
    }
}
