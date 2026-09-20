<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\TotpProvisioningStore;
use Heidi\Bundle\Http\TwoFactorPage;
use Heidi\Core\Application\Totp\TotpEnrolment;
use Heidi\Core\Exception\CredentialEnrolmentFailedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The first step of the enrolment of an authenticator app (architecture §5.2): the provisioning drawn
 * by the enrolment of the core for the signed-in user, kept sealed in the session of this browser for
 * the code that comes back, and shown as a QR code and as a key. A user who holds an app already is
 * refused, they remove it first; nothing is written until the first code holds.
 */
#[AsController]
final readonly class TotpEnrolmentBeginController
{
    public const string ROUTE = 'heidi_interaction_account_two_factor_begin';

    public const string CSRF_TOKEN_ID = 'heidi_two_factor_begin';

    public const string ALREADY_ENROLLED = 'already_enrolled';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private TotpEnrolment $enrolment,
        private TotpProvisioningStore $provisionings,
        private TwoFactorPage $page,
    ) {
    }

    #[Route('/account/two-factor/begin', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $user = $session->user;
        try {
            $provisioning = $this->enrolment->begin($user);
        } catch (CredentialEnrolmentFailedException) {
            return $this->page->render($user, self::ALREADY_ENROLLED, Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $this->provisionings->store($request->getSession(), $user, $provisioning, $this->contexts->fromRequest($request)->receivedAt);

        return $this->page->renderEnrolment($user, $provisioning);
    }
}
