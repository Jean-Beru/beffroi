<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\DeviceApprovalPage;
use Heidi\Bundle\Http\FormToken;
use Heidi\Bundle\Http\LoginTarget;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Core\Port\CodeAttemptLimiterInterface;
use Heidi\Oidc\Application\Device\DeviceApproval;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationResponse;
use Heidi\Oidc\Domain\Device\UserCode;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Where a user types the code an appliance is showing and says yes or no (RFC 8628 §3.3, BCP 10027 §2): the
 * one screen of the whole flow, and the only part of it no specification writes for us.
 *
 * The user signs in before the code is read at all: a request approved by nobody is a request approved by
 * nobody, and the attempts at a code are counted against the person making them, as every other code typed
 * on a page of this provider is (decision 0014). The page they were on is remembered (LoginTarget), the
 * login of the firewall is the one every other page of the provider uses, and the browser lands back on the
 * code it carried.
 *
 * Nothing is approved on a GET. The complete verification URI of §3.3.1 brings the code already typed, and
 * what it gets is the same page asking for a confirmation: a link followed from a television screen, or
 * prefetched by whatever the browser hands the address to, must not be an approval. The act is a POST with
 * the token this page rendered.
 *
 * A code that names no request awaiting an answer gets one refusal whatever the reason, and only the
 * refusals are counted: thirty-four bits of code are enough only if guessing is slow (§5.1, §5.2), and a
 * user who typed the right code has guessed nothing.
 */
#[AsController]
final readonly class DeviceVerificationController
{
    public const string ROUTE = 'heidi_interaction_device';

    public const string CSRF_TOKEN_ID = 'heidi_device';

    public const string ANSWER_PARAMETER = 'answer';

    public const string ANSWER_ALLOW = 'allow';

    public const string ANSWER_DENY = 'deny';

    public function __construct(
        private TenantProvider $tenants,
        private DeviceApproval $approval,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private DeviceApprovalPage $page,
        private FormToken $formTokens,
        private LoginTarget $loginTargets,
        private CodeAttemptLimiterInterface $attempts,
    ) {
    }

    #[Route('/device', name: self::ROUTE, methods: ['GET', 'POST'])]
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
        $typed = $parameters[DeviceAuthorizationResponse::USER_CODE_PARAMETER] ?? null;
        $typed = is_string($typed) ? UserCode::normalize($typed) : '';

        $session = $this->browser->authenticationSession($request, $tenant);
        if ($session === null) {
            // remembered so that the login of the firewall brings the browser back to the code it carried
            return $this->loginTargets->sendToLogin(
                $request->getSession(),
                self::ROUTE,
                UserCode::isWellFormed($typed)
                    ? [
                        DeviceAuthorizationResponse::USER_CODE_PARAMETER => $typed,
                    ] : [],
            );
        }
        // the page is no longer waiting for a login, whatever it does with the code next
        $this->loginTargets->forget($request->getSession());
        if ($typed === '') {
            return $this->page->renderForm();
        }
        // What is compared and what is shown are two readings of one code (UserCode): the lookup is made by
        // the bare value, and the page shows the code as the appliance shows it, so that the user sees at a
        // glance that it is theirs (BCP 10027 §2).
        $shown = UserCode::shown($typed);
        if (! $this->attempts->mayAttempt($session->user)) {
            return $this->page->renderForm(DeviceApprovalPage::TOO_MANY_ATTEMPTS, $shown, Response::HTTP_TOO_MANY_REQUESTS);
        }
        $record = $this->approval->awaitingAnAnswer($tenant, $typed);
        if ($record === null) {
            $this->attempts->attempt($session->user);

            return $this->page->renderForm(DeviceApprovalPage::UNKNOWN_CODE, $shown, Response::HTTP_BAD_REQUEST);
        }

        $answer = $parameters[self::ANSWER_PARAMETER] ?? null;
        if (! $request->isMethod('POST') || $answer !== self::ANSWER_ALLOW && $answer !== self::ANSWER_DENY) {
            return $this->page->renderApproval($record, $session->user, $shown);
        }
        if ($answer === self::ANSWER_DENY) {
            $this->approval->deny($record);
        } else {
            $this->approval->approve($record, $session, $this->contexts->fromRequest($request));
        }

        return $this->page->renderAnswer($record);
    }
}
