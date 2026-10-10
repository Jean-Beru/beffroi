<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Authentication\OtherSessionsTermination;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Every session of the signed-in user but this browser's, ended from the page of the account (architecture
 * §5.2): one act for what a person would otherwise do one line at a time, and the browser they are reading
 * from stays signed in.
 *
 * There is no identifier in the request: what is kept is the session the reader presents, so no list of
 * what to end travels and nothing of somebody else is reachable from here.
 */
#[AsController]
final readonly class AccountOtherSessionsRevocationController
{
    public const string ROUTE = 'beffroi_interaction_account_sessions_revoke_others';

    public const string CSRF_TOKEN_ID = 'beffroi_sessions_revoke_others';

    public function __construct(
        private AccountAccess $account,
        private OtherSessionsTermination $termination,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/sessions/revoke-others', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $this->termination->endEveryOther($session, $this->contexts->fromRequest($request));

        return $this->pages->afterTheForm(AccountSessionsController::ROUTE);
    }
}
