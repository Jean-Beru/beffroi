<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

use Beffroi\Bundle\Controller\AccountSignInsController;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use function count;

/**
 * The recent sign-ins, on the home page of the account (issue #454): how many attempts of the last ones
 * read failed. It is that number and not the count of the successes, because a success is what a person
 * expects and a failure is what they came to look for.
 */
final readonly class SignInsSection implements AccountSectionInterface
{
    public function __construct(
        private ActsOfAPersonInterface $acts,
    ) {
    }

    /**
     * How many of the last acts of this person a refusal is counted among: the home of the account says
     * that somebody tried and did not recently, which is a number of attempts and not of days. The page
     * itself is read in pages (AskedPage) and is bounded by nothing.
     */
    public const int AMONG_THE_LAST = 20;

    public function route(): string
    {
        return AccountSignInsController::ROUTE;
    }

    public function title(): string
    {
        return 'sign_ins.title';
    }

    public function state(User $user): AccountSectionState
    {
        return new AccountSectionState('account.sign_ins.state', [
            'count' => count($this->acts->lastOf($user, [AuthenticationFailed::NAME], self::AMONG_THE_LAST)),
        ]);
    }
}
