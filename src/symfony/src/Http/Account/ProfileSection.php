<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

use function count;
use Beffroi\Bundle\Controller\AccountProfileController;
use Beffroi\Core\Domain\Identity\User;

/**
 * What this provider holds about the person, on the home page: how much of it they told us. What each
 * thing is, and what the account itself holds beside it, is on the page of the information.
 */
final readonly class ProfileSection implements AccountSectionInterface
{
    public function route(): string
    {
        return AccountProfileController::ROUTE;
    }

    public function title(): string
    {
        return 'profile.title';
    }

    public function state(User $user): AccountSectionState
    {
        return new AccountSectionState('account.profile.state', [
            'count' => count(RecordedInformation::claimsOf($user)),
        ]);
    }
}
