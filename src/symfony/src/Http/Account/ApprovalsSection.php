<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

use function count;
use Beffroi\Bundle\Controller\PendingApprovalsController;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Application\Ciba\BackchannelApproval;

/**
 * What is waiting for an answer from this user, on the home page (CIBA Core §10.1). First of the sections
 * and not last: every other page of the account says what the account holds, and this one says that
 * somebody is waiting on it now.
 *
 * It is what makes the page findable at all. A user who is told from outside that something is waiting is
 * told nothing of the request and handed no link that answers it (BCP 10027 §5.2), so what they have is the
 * provider they already know, and the way in to it is their account.
 */
final readonly class ApprovalsSection implements AccountSectionInterface
{
    public function __construct(
        private BackchannelApproval $approval,
    ) {
    }

    public function route(): string
    {
        return PendingApprovalsController::ROUTE;
    }

    public function title(): string
    {
        return 'approvals.title';
    }

    public function state(User $user): AccountSectionState
    {
        return new AccountSectionState('account.approvals.state', [
            'count' => count($this->approval->awaitingAnAnswerBy($user)),
        ]);
    }
}
