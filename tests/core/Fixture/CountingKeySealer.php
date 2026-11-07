<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeySealerInterface;
use SensitiveParameter;

final class CountingKeySealer implements KeySealerInterface
{
    public private(set) int $unsealed = 0;

    public function seal(Tenant $tenant, #[SensitiveParameter] array $privateJwk): string
    {
        return Keys::sealer()->seal($tenant, $privateJwk);
    }

    public function unseal(Tenant $tenant, #[SensitiveParameter] string $sealed): array
    {
        ++$this->unsealed;

        return Keys::sealer()->unseal($tenant, $sealed);
    }
}
