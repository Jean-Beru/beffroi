<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Port\CredentialChangeNotifierInterface;

final class RecordingCredentialChangeNotifier implements CredentialChangeNotifierInterface
{
    /**
     * @var list<CredentialChange>
     */
    public private(set) array $told = [];

    public function tell(CredentialChange $change): void
    {
        $this->told[] = $change;
    }

    /**
     * @return list<array{string, ?string}> the act and the kind of each change told, in the order they were
     */
    public function acts(): array
    {
        $acts = [];
        foreach ($this->told as $change) {
            $acts[] = [$change->act, $change->kind];
        }

        return $acts;
    }
}
