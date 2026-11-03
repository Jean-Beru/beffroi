<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\Account\AsksForARecentProofInterface;
use App\Http\Account\BreachedPasswordDemand;
use App\Http\AccountAccess;
use App\Http\InteractionPages;
use App\Http\RequestContextFactory;
use App\Http\WhatWasRefused;
use Beffroi\Core\Application\Authentication\OtherSessionsTermination;
use Beffroi\Core\Application\Credential\PasswordChange;
use Beffroi\Core\Domain\Credential\PasswordLength;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Exception\PasswordChangeRefusedException;
use Beffroi\Core\Exception\PasswordRefusedException;
use function hash_equals;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The password of the signed-in person replaced by them (architecture §5.2): they prove who they are
 * again, type the one in use, pose another twice, and every other browser signed in as them is signed out.
 *
 * **A session alone does not post it** (AsksForARecentProofInterface): the same window the page is read
 * under bounds the post, because a guard the form does not repeat is a guard a form post goes around. The
 * browser is sent to the login of the firewall and comes back to the page, where the form is typed again.
 *
 * **The password posed is typed twice.** A password nobody can read back is a password nobody can check
 * they typed right, and somebody who mistypes it twice the same way has lost the account rather than
 * changed it; the two are compared with hash_equals, as the console does on its two prompts.
 *
 * **Signing the others out is this page's policy and not the core's**, which writes the password and says
 * so: a password is replaced because the one before it is not trusted any more, and a session opened under
 * it is exactly what should not outlive it. The browser this was asked from stays signed in, because
 * asking for a password is not a reason to ask for it twice.
 *
 * It answers with a redirection whether the password was written or refused (issue #481), so a browser
 * reloading the page it comes back to does not post a password again; what was refused crosses the
 * redirection in the session and the page says which rule pronounced it.
 *
 * **A password written carries the browser on to the page that was waiting for the login that was sent
 * here** (BreachedPasswordDemand, issue #579), and to the page of the password when none was: the demand
 * is answered by the password itself, so nothing of it is read back here and nothing of it outlives the
 * credential it was made about.
 */
#[AsController]
final readonly class AccountPasswordChangeController implements AsksForARecentProofInterface
{
    public const string ROUTE = 'beffroi_interaction_account_password_change';

    public const string CSRF_TOKEN_ID = 'beffroi_password_change';

    public const string IN_USE_PARAMETER = 'current_password';

    public const string POSED_PARAMETER = 'new_password';

    public const string POSED_AGAIN_PARAMETER = 'new_password_again';

    /**
     * The password was posed twice and the two are not the same, so neither is what was meant.
     */
    public const string NOT_CONFIRMED = 'not_confirmed';

    public function __construct(
        private AccountAccess $account,
        private PasswordChange $change,
        private OtherSessionsTermination $others,
        private RequestContextFactory $contexts,
        private WhatWasRefused $refusals,
        private BreachedPasswordDemand $demands,
        private InteractionPages $pages,
    ) {
    }

    /**
     * The page of the password, which holds the form this posts.
     */
    public function comesBackTo(): string
    {
        return AccountPasswordController::ROUTE;
    }

    #[Route('/account/password', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $posed = $request->request->getString(self::POSED_PARAMETER);
        if (! hash_equals($posed, $request->request->getString(self::POSED_AGAIN_PARAMETER))) {
            return $this->refused($request, self::NOT_CONFIRMED);
        }
        $context = $this->contexts->fromRequest($request);

        try {
            $this->change->change(
                $session->user,
                $request->request->getString(self::IN_USE_PARAMETER),
                new PlainPassword($posed, PasswordLength::under($session->user->tenant->loginFloor)),
                $context,
            );
        } catch (PasswordRefusedException $exception) {
            // what a password has to be, and what a list of compromised passwords said of this one
            return $this->refused($request, $exception->refusal->value);
        } catch (PasswordChangeRefusedException $exception) {
            return $this->refused($request, $exception->refusal->value);
        }
        $this->others->endEveryOther($session, $context);

        return $this->demands->answered($request->getSession()) ?? $this->pages->afterTheForm(AccountPasswordController::ROUTE);
    }

    private function refused(Request $request, string $code): Response
    {
        $this->refusals->keep($request, $code);

        return $this->pages->afterTheForm(AccountPasswordController::ROUTE);
    }
}
