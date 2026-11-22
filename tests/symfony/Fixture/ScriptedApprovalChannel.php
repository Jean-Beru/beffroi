<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Ciba\PendingApprovalChannelInterface;
use App\Messenger\NotificationNotDeliveredException;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Ciba\PendingApproval;

/**
 * A channel that answers as it was scripted to: the person reached, a person it has no way to reach, or a refusal a
 * later attempt may lift. It counts how many times it was asked.
 */
final class ScriptedApprovalChannel implements PendingApprovalChannelInterface
{
    public int $told = 0;

    private function __construct(
        private readonly bool $reaches,
        private readonly ?string $refusal,
    ) {
    }

    public static function reaching(): self
    {
        return new self(true, null);
    }

    public static function reachingNobody(): self
    {
        return new self(false, null);
    }

    public static function refusing(string $detail): self
    {
        return new self(false, $detail);
    }

    public function tell(User $user, PendingApproval $approval): bool
    {
        ++$this->told;
        if ($this->refusal !== null) {
            throw new NotificationNotDeliveredException($this->refusal);
        }

        return $this->reaches;
    }
}
