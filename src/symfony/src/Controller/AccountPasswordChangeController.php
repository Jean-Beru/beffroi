<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Core\Application\Authentication\OtherSessionsTermination;
use Beffroi\Core\Application\Credential\PasswordChange;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\PasswordChangeRefusedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The password of the signed-in person replaced by them (architecture §5.2): they type the one in use,
 * pose another, and every other browser signed in as them is signed out.
 *
 * **Signing the others out is this page's policy and not the core's**, which writes the password and says
 * so: a password is replaced because the one before it is not trusted any more, and a session opened
 * under it is exactly what should not outlive it. The browser this was asked from stays signed in,
 * because asking for a password is not a reason to ask for it twice.
 *
 * It answers with a redirection whether the password was written or refused (issue #481), so a browser
 * reloading the page it comes back to does not post a password again; what was refused crosses the
 * redirection in the session and the page says which of the refusals it was.
 */
#[AsController]
final readonly class AccountPasswordChangeController
{
    public const string ROUTE = 'beffroi_interaction_account_password_change';

    public const string CSRF_TOKEN_ID = 'beffroi_password_change';

    public const string IN_USE_PARAMETER = 'current_password';

    public const string POSED_PARAMETER = 'new_password';

    /**
     * What was posed is not a password this provider holds: too short, or longer than anything is.
     */
    public const string NOT_A_PASSWORD = 'not_a_password';

    public function __construct(
        private AccountAccess $account,
        private PasswordChange $change,
        private OtherSessionsTermination $others,
        private RequestContextFactory $contexts,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/password', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $context = $this->contexts->fromRequest($request);

        try {
            $this->change->change(
                $session->user,
                $request->request->getString(self::IN_USE_PARAMETER),
                new PlainPassword($request->request->getString(self::POSED_PARAMETER)),
                $context,
            );
        } catch (InvalidArgumentException) {
            return $this->refused($request, self::NOT_A_PASSWORD);
        } catch (PasswordChangeRefusedException $exception) {
            return $this->refused($request, $exception->refusal->value);
        }
        $this->others->endEveryOther($session, $context);

        return $this->pages->afterTheForm(AccountPasswordController::ROUTE);
    }

    private function refused(Request $request, string $code): Response
    {
        $this->refusals->keep($request, $code);

        return $this->pages->afterTheForm(AccountPasswordController::ROUTE);
    }
}
