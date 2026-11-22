<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Ciba\PendingApprovalChannelInterface;
use App\Messenger\NotificationNotDeliveredException;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Ciba\PendingApproval;

/**
 * A channel that answers as it was scripted to: the person reached, a person it has no way to reach, or a refusal a
 * later attempt may lift. It counts how many times it was asked, and is web push unless it is named otherwise.
 */
final class ScriptedApprovalChannel implements PendingApprovalChannelInterface
{
    public int $told = 0;

    private function __construct(
        private readonly bool $reaches,
        private readonly ?string $refusal,
        private readonly string $channel,
    ) {
    }

    public static function reaching(string $channel = 'web_push'): self
    {
        return new self(true, null, $channel);
    }

    public static function reachingNobody(): self
    {
        return new self(false, null, 'web_push');
    }

    public static function refusing(string $detail): self
    {
        return new self(false, $detail, 'web_push');
    }

    public function name(): string
    {
        return $this->channel;
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
