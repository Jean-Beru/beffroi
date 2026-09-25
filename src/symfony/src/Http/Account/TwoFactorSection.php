<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http\Account;

use Heidi\Bundle\Controller\AccountTwoFactorController;
use Heidi\Core\Application\Totp\ActiveTotp;
use Heidi\Core\Domain\Identity\User;

/**
 * The second factor of the account, on the home page: the authenticator app it holds, or none. How many
 * backup codes are left is on the page of the second factor, where they can be renewed.
 */
final readonly class TwoFactorSection implements AccountSectionInterface
{
    public function __construct(
        private ActiveTotp $activeTotp,
    ) {
    }

    public function route(): string
    {
        return AccountTwoFactorController::ROUTE;
    }

    public function title(): string
    {
        return 'two_factor.title';
    }

    public function state(User $user): AccountSectionState
    {
        return new AccountSectionState(
            $this->activeTotp->of($user) === null
                ? 'account.two_factor.state.none'
                : 'account.two_factor.state.active',
        );
    }
}
