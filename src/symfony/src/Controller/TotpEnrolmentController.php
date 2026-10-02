<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\TotpProvisioningStore;
use Beffroi\Bundle\Http\TwoFactorPage;
use Beffroi\Core\Application\Totp\TotpEnrolment;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The first code of a new authenticator app, posted by the enrolment page with the CSRF token
 * (architecture §5.2): verified by the enrolment of the core against the provisioning this browser holds
 * for this user; the credential exists from here, and the backup codes are shown, this once. A code that
 * does not match shows the same QR code again; without a provisioning, the page of the account says so.
 */
#[AsController]
final readonly class TotpEnrolmentController
{
    public const string ROUTE = 'beffroi_interaction_account_two_factor_enrol';

    public const string CSRF_TOKEN_ID = 'beffroi_two_factor_enrol';

    public const string CODE_PARAMETER = 'code';

    public const string NO_PROVISIONING = 'no_provisioning';

    public const string REFUSED = 'refused';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private TotpEnrolment $enrolment,
        private TotpProvisioningStore $provisionings,
        private TwoFactorPage $page,
    ) {
    }

    #[Route('/account/two-factor', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $user = $session->user;
        $context = $this->contexts->fromRequest($request);
        $provisioning = $this->provisionings->provisioning($request->getSession(), $user, $context->receivedAt);
        if ($provisioning === null) {
            return $this->page->render($user, self::NO_PROVISIONING, Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $code = $request->request->getString(self::CODE_PARAMETER);
        try {
            $this->enrolment->complete($user, $provisioning, $code, $context);
        } catch (CredentialEnrolmentFailedException) {
            return $this->page->renderEnrolment($user, $provisioning, self::REFUSED, Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $this->provisionings->forget($request->getSession());

        return $this->page->renderEnrolled($user, $provisioning->backupCodes);
    }
}
