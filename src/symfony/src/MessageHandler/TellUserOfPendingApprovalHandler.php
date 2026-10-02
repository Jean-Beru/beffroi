<?php

declare(strict_types=1);

namespace Beffroi\Bundle\MessageHandler;

use Beffroi\Bundle\Ciba\PendingApprovalChannelInterface;
use Beffroi\Bundle\Message\TellUserOfPendingApproval;
use Beffroi\Core\Port\UserRepositoryInterface;
use Symfony\Component\Messenger\Attribute\AsMessageHandler;

/**
 * Hands one user to every way this deployment has of reaching them (CIBA Core §7). The user is read here
 * and not carried on the message: what a channel needs of somebody is whatever that channel sends to, and
 * a message that carried an address would carry a stale one.
 *
 * A user who is no longer there, or who belongs to another tenant than the request that named them, is
 * reached by nobody and nothing is said about it: the request stays where it is and expires unanswered,
 * which is what it would do anyway.
 */
#[AsMessageHandler(bus: 'command.bus')]
final readonly class TellUserOfPendingApprovalHandler
{
    /**
     * @param iterable<PendingApprovalChannelInterface> $channels in the order they are wired; the bundle
     *                                                            wires none
     */
    public function __construct(
        private UserRepositoryInterface $users,
        private iterable $channels,
    ) {
    }

    public function __invoke(TellUserOfPendingApproval $message): void
    {
        $approval = $message->approval;
        $user = $this->users->find($approval->userId);
        if ($user === null || ! $user->tenant->equals($approval->tenant)) {
            return;
        }
        foreach ($this->channels as $channel) {
            $channel->tell($user, $approval);
        }
    }
}
