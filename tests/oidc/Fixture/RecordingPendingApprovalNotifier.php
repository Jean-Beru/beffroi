<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\Ciba\PendingApproval;
use Beffroi\Oidc\Port\PendingApprovalNotifierInterface;

/**
 * CIBA Core §7
 */
final class RecordingPendingApprovalNotifier implements PendingApprovalNotifierInterface
{
    /**
     * @var list<PendingApproval>
     */
    public private(set) array $told = [];

    public function tell(PendingApproval $approval): void
    {
        $this->told[] = $approval;
    }
}
