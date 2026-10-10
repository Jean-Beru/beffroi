<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

use Beffroi\Bundle\Controller\AccountPasswordController;
use Beffroi\Bundle\Http\PasswordPage;
use Beffroi\Core\Domain\Identity\User;
use Psr\Clock\ClockInterface;

/**
 * The password, on the home page of the account (architecture §5.2): when it was last written, which is
 * the one thing a person can read of a password, or that they hold none and sign in by another means.
 */
final readonly class PasswordSection implements AccountSectionInterface
{
    public function __construct(
        private PasswordPage $page,
        private ClockInterface $clock,
    ) {
    }

    public function route(): string
    {
        return AccountPasswordController::ROUTE;
    }

    public function title(): string
    {
        return 'password.title';
    }

    public function state(User $user): AccountSectionState
    {
        $password = $this->page->of($user);

        if ($password === null) {
            return new AccountSectionState('account.password.none');
        }

        // how long ago it was written rather than the day it was: what a line of the home page says of a
        // page is how much there is to see on it, and the date itself is read on the page
        return new AccountSectionState('account.password.state', [
            'days' => (int) $this->clock->now()->diff($password->hashChangedAt)->days,
        ]);
    }
}
