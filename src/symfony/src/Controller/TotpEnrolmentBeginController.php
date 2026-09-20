<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\TotpProvisioningStore;
use Heidi\Bundle\Http\TwoFactorPage;
use Heidi\Core\Application\Totp\TotpEnrolment;
use Heidi\Core\Exception\CredentialEnrolmentFailedException;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

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
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private TotpEnrolment $enrolment,
        private TotpProvisioningStore $provisionings,
        private CsrfTokenManagerInterface $csrf,
        private TwoFactorPage $page,
        private InteractionPages $pages,
    ) {
    }

    #[Route('/account/two-factor/begin', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->browser->authenticationSession($request, $this->tenants->provide());
        if ($session === null) {
            return $this->pages->error(Response::HTTP_UNAUTHORIZED, AccountPasskeysController::LOGIN_REQUIRED);
        }
        $token = $request->request->get('_token');
        if (! is_string($token) || ! $this->csrf->isTokenValid(new CsrfToken(self::CSRF_TOKEN_ID, $token))) {
            return $this->pages->error(Response::HTTP_FORBIDDEN, ConsentController::INVALID_CSRF_TOKEN);
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
