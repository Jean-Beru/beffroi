<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

use Beffroi\Bundle\Controller\AccountArchiveController;
use Beffroi\Bundle\Http\ArchiveState;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use Psr\Clock\ClockInterface;

/**
 * The archive of everything held about this person, on the home page of the account (issue #453): which
 * state their last request is in, so that a person who asked yesterday learns here whether their file is
 * waiting for them.
 *
 * It reads that state where the page of the archive reads it (ArchiveState), so the three words here and
 * the sentence there are never two readings of the same row.
 */
final readonly class ArchiveSection implements AccountSectionInterface
{
    public function __construct(
        private PersonalArchiveRepositoryInterface $archives,
        private ClockInterface $clock,
    ) {
    }

    public function route(): string
    {
        return AccountArchiveController::ROUTE;
    }

    public function title(): string
    {
        return 'archive.title';
    }

    public function state(User $user): AccountSectionState
    {
        return new AccountSectionState('account.archive.' . ArchiveState::of($this->archives->latestOf($user), $this->clock->now()));
    }
}
