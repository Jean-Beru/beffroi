<?php

declare(strict_types=1);

namespace App\Http\Account;

use function count;
use App\Controller\AccountNotificationsController;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\PushSubscriptionRepositoryInterface;

/**
 * The browsers of the account this provider may push to, on the home page: how many of them are still
 * reachable. A subscription that was taken out is on the page of the notifications, where its date is,
 * and is counted nowhere.
 */
final readonly class NotificationsSection implements AccountSectionInterface
{
    public function __construct(
        private PushSubscriptionRepositoryInterface $subscriptions,
    ) {
    }

    public function route(): string
    {
        return AccountNotificationsController::ROUTE;
    }

    public function title(): string
    {
        return 'notifications.title';
    }

    public function state(User $user): AccountSectionState
    {
        return new AccountSectionState('account.notifications.state', [
            'count' => count($this->subscriptions->findActiveByUser($user)),
        ]);
    }
}
