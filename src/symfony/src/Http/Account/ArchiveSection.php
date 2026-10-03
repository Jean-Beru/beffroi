<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

use Beffroi\Bundle\Controller\AccountArchiveController;
use Beffroi\Bundle\Http\ArchivePage;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use Psr\Clock\ClockInterface;

/**
 * The archive of everything held about this person, on the home page of the account (issue #453): which of
 * the four states their last request is in, so that a person who asked yesterday learns here whether
 * their file is waiting for them.
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
        $archive = $this->archives->latestOf($user);
        $now = $this->clock->now();
        if ($archive === null || $archive->hasExpired($now)) {
            return new AccountSectionState('account.archive.' . ($archive === null ? ArchivePage::NEVER : ArchivePage::EXPIRED));
        }

        return new AccountSectionState('account.archive.' . ($archive->isReady() ? ArchivePage::READY : ArchivePage::BEING_BUILT));
    }
}
