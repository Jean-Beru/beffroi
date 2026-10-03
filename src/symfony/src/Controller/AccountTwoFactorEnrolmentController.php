<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\TotpProvisioningStore;
use Beffroi\Bundle\Http\TwoFactorPage;
use Beffroi\Bundle\Http\WhatWasRefused;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The enrolment of an authenticator app in progress (architecture §5.2): the QR code, the key for a manual
 * entry, and the field the first code is typed into.
 *
 * **It is a page and not the answer of a form** (issue #481). The step that draws the provisioning posts,
 * and a POST whose answer is this page is a page a browser offers to send again: reloading it would draw a
 * second secret and quietly make the QR code being scanned worthless. So the step that draws redirects
 * here, and here reads what it drew from the session of this browser (TotpProvisioningStore).
 *
 * A browser with nothing drawn is sent back to the page of the second factor saying so, which is what a
 * person reloading this page past the ten minutes of a provisioning gets.
 */
#[AsController]
final readonly class AccountTwoFactorEnrolmentController
{
    public const string ROUTE = 'beffroi_interaction_account_two_factor_enrolment';

    public function __construct(
        private AccountAccess $account,
        private TotpProvisioningStore $provisionings,
        private RequestContextFactory $contexts,
        private WhatWasRefused $refusals,
        private TwoFactorPage $page,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/two-factor/enrol', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }
        $refusal = $this->refusals->take($request);
        $provisioning = $this->provisionings->provisioning(
            $request->getSession(),
            $session->user,
            $this->contexts->fromRequest($request)->receivedAt,
        );
        if ($provisioning === null) {
            $this->refusals->keep($request, TotpEnrolmentController::NO_PROVISIONING);

            return $this->pages->afterTheForm(AccountTwoFactorController::ROUTE);
        }

        return $this->page->renderEnrolment($session->user, $provisioning, $refusal?->code);
    }
}
