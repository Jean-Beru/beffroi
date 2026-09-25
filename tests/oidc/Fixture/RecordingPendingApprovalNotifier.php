<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Oidc\Domain\Ciba\PendingApproval;
use Heidi\Oidc\Port\PendingApprovalNotifierInterface;

/**
 * What a deployment wires to reach its users (CIBA Core §7), here keeping what it was asked to carry so
 * that a test reads it.
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
