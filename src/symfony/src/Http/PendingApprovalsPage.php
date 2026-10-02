<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Symfony\Component\HttpFoundation\Response;

/**
 * The one screen of the backchannel flow (CIBA Core §10.1, BCP 10027 §5.2), in its two states: what is
 * waiting for this user, and the answer once it is given.
 *
 * A request is named and not summarised: the provider that is asking, the client that asked, the message
 * that client wrote, the address it asked from and every scope it asked for, so that somebody who started
 * nothing can tell that they started nothing. The message is the one thing on the page a third party
 * wrote, and it is shown as what it is, beside the name of the client and never in place of the
 * provider's own words.
 */
final readonly class PendingApprovalsPage
{
    /**
     * The request the form named is not one this user may answer any more: answered, expired, spent, or
     * never theirs. One message for the four, which is also all there is to say about it.
     */
    public const string NOTHING_TO_ANSWER = 'nothing_to_answer';

    public function __construct(
        private InteractionPages $pages,
    ) {
    }

    /**
     * @param list<BackchannelAuthenticationRecord> $records what is waiting for this user, oldest first
     * @param string|null $refusal a code the template translates
     */
    public function renderList(
        Tenant $tenant,
        User $user,
        array $records,
        ?string $refusal = null,
        int $status = Response::HTTP_OK,
    ): Response {
        return $this->pages->render(
            'approvals.html.twig',
            [
                'tenant' => $tenant,
                'user' => $user,
                'records' => $records,
                'refusal' => $refusal,
            ],
            $status,
        );
    }

    public function renderAnswer(BackchannelAuthenticationRecord $record): Response
    {
        return $this->pages->render('approval_answered.html.twig', [
            'record' => $record,
            'client' => $record->client,
            'approved' => $record->isApproved(),
        ]);
    }
}
