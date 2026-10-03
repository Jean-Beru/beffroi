<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\FormToken;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Http\PendingApprovalsPage;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\RequestParameters;
use Beffroi\Bundle\Http\StepUpOffer;
use Beffroi\Oidc\Application\Ciba\BackchannelApproval;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Where a user answers the requests made for them somewhere else (CIBA Core §10.1, BCP 10027 §5.2): the
 * one screen of the flow, and the part no specification writes for us.
 *
 * The user signs in first and the page then shows what is waiting for them, and nothing else. There is no
 * code to type and no link that carries a request: what reaches a user from outside says that something
 * is waiting and sends them to the provider they already know, and what they find here is found by who
 * they are. That is the whole of the answer to the attack BCP 10027 is written about, and it is why this
 * page takes no identifier from anywhere but its own list.
 *
 * Nothing is approved on a GET, and a request is named to the POST by a handle of that very list: a
 * request of somebody else is not in it, so it is not answerable, signed in or not.
 *
 * What the client asked the authentication to reach is answered here (CIBA Core §7.1, decision 0010), and
 * it is answered by asking the user rather than by refusing the client: a session that proves none of the
 * requested classes, when a credential of that user would, is sent to the login of this provider for one
 * more proof and comes back here to answer. It is asked again at each attempt and never given up on, the
 * page always offering the refusal that ends the request (§11) and the request expiring on its own
 * otherwise; a class nothing of this user could ever reach is asked for by nobody, the demand being a
 * request and not a condition (OIDC Core §5.5.1.1) and the "acr" of the tokens saying what was proven.
 */
#[AsController]
final readonly class PendingApprovalsController
{
    public const string ROUTE = 'beffroi_interaction_account_approvals';

    public const string CSRF_TOKEN_ID = 'beffroi_approvals';

    public const string REQUEST_PARAMETER = 'request';

    public const string ANSWER_PARAMETER = 'answer';

    public const string ANSWER_ALLOW = 'allow';

    public const string ANSWER_DENY = 'deny';

    public function __construct(
        private TenantProvider $tenants,
        private BackchannelApproval $approval,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private PendingApprovalsPage $page,
        private FormToken $formTokens,
        private LoginTarget $loginTargets,
    ) {
    }

    #[Route('/account/approvals', name: self::ROUTE, methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $parameters = RequestParameters::ofBrowserRequest($request);
        if ($request->isMethod('POST')) {
            $refusal = $this->formTokens->refusal($parameters[FormToken::PARAMETER] ?? null, self::CSRF_TOKEN_ID);
            if ($refusal !== null) {
                return $refusal;
            }
        }

        $session = $this->browser->authenticationSession($request, $tenant);
        if ($session === null) {
            // remembered so that the login of the firewall brings the browser back to this page
            return $this->loginTargets->sendToLogin($request->getSession(), self::ROUTE, []);
        }
        $this->loginTargets->forget($request->getSession());
        $user = $session->user;
        if (! $request->isMethod('POST')) {
            return $this->page->renderList($user, $this->approval->awaitingAnAnswerBy($user));
        }

        $handle = $parameters[self::REQUEST_PARAMETER] ?? null;
        $record = is_string($handle) ? $this->approval->awaitingAnAnswerFrom($user, $handle) : null;
        $answer = $parameters[self::ANSWER_PARAMETER] ?? null;
        if ($record === null || $answer !== self::ANSWER_ALLOW && $answer !== self::ANSWER_DENY) {
            // the request was answered, expired or was never this user's: the list says what is left
            return $this->page->renderList(
                $user,
                $this->approval->awaitingAnAnswerBy($user),
                PendingApprovalsPage::NOTHING_TO_ANSWER,
                Response::HTTP_BAD_REQUEST,
            );
        }
        if ($answer === self::ANSWER_DENY) {
            $this->approval->deny($record, $this->contexts->fromRequest($request));

            return $this->page->renderAnswer($record);
        }
        $stepUp = $this->approval->stepUpFor($record, $session);
        if ($stepUp !== null) {
            // the client asked for a class this session does not prove and a credential of this user
            // would: the login of the firewall is where one more proof is given, and this page is where
            // the browser comes back to answer (decision 0010)
            return $this->loginTargets->sendToLogin($request->getSession(), self::ROUTE, [], StepUpOffer::of($stepUp));
        }
        $this->approval->approve($record, $session, $this->contexts->fromRequest($request));

        return $this->page->renderAnswer($record);
    }
}
