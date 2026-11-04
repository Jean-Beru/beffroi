<?php

declare(strict_types=1);

namespace App\Http\Account;

use App\Controller\AccountActsController;
use function array_filter;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use function count;

/**
 * What happened to the account, on its home page (issues #454, #571 and #842): how many of the last
 * attempts to sign in as this person were refused. It is that number and not the count of the successes,
 * because a success is what a person expects and a failure is what they came to look for; the page behind
 * it holds every act of the account, and this one line says the one thing that brings somebody to open it.
 */
final readonly class ActsSection implements AccountSectionInterface
{
    public function __construct(
        private ActsOfAPersonInterface $acts,
    ) {
    }

    /**
     * How many of the last attempts to sign in as this person the refusals are counted among: the home of
     * the account says that somebody tried and did not recently, which is a number of attempts and not of
     * days, so a refusal leaves the count once that many attempts have followed it. The page itself is read
     * in pages (AskedPage) and is bounded by nothing.
     */
    public const int AMONG_THE_LAST = 20;

    /**
     * What an attempt to sign in as this person is: one that got in, or one that did not. A proof is how a
     * sign-in got in and not an attempt of its own, and the other acts of an account are nobody trying, so
     * none of them takes the place of an attempt among the last ones.
     *
     * @var list<string>
     */
    private const array ATTEMPTS = [UserAuthenticated::NAME, AuthenticationFailed::NAME];

    public function route(): string
    {
        return AccountActsController::ROUTE;
    }

    public function title(): string
    {
        return 'acts.title';
    }

    public function state(User $user): AccountSectionState
    {
        $attempts = $this->acts->lastOf($user, self::ATTEMPTS, self::AMONG_THE_LAST);

        return new AccountSectionState('account.acts.state', [
            'count' => count(array_filter($attempts, static fn (JournalEntry $attempt): bool => $attempt->act === AuthenticationFailed::NAME)),
        ]);
    }
}
