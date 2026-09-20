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
use Heidi\Core\Exception\InvalidArgumentException;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * The first code of a new authenticator app, posted by the enrolment page with the CSRF token
 * (architecture §5.2): verified by the enrolment of the core against the provisioning this browser holds
 * for this user; the credential exists from here, and the backup codes are shown, this once. A code that
 * does not match shows the same QR code again; without a provisioning, the page of the account says so.
 */
#[AsController]
final readonly class TotpEnrolmentController
{
    public const string ROUTE = 'heidi_interaction_account_two_factor_enrol';

    public const string CSRF_TOKEN_ID = 'heidi_two_factor_enrol';

    public const string CODE_PARAMETER = 'code';

    public const string NO_PROVISIONING = 'no_provisioning';

    public const string REFUSED = 'refused';

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

    #[Route('/account/two-factor', name: self::ROUTE, methods: ['POST'])]
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
        $context = $this->contexts->fromRequest($request);
        $provisioning = $this->provisionings->provisioning($request->getSession(), $user, $context->receivedAt);
        if ($provisioning === null) {
            return $this->page->render($user, self::NO_PROVISIONING, Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $code = $request->request->get(self::CODE_PARAMETER);
        try {
            $this->enrolment->complete($user, '', $provisioning, is_string($code) ? $code : '', $context);
        } catch (CredentialEnrolmentFailedException|InvalidArgumentException) {
            return $this->page->renderEnrolment($user, $provisioning, self::REFUSED, Response::HTTP_UNPROCESSABLE_ENTITY);
        }
        $this->provisionings->forget($request->getSession());

        return $this->page->renderEnrolled($user, $provisioning->backupCodes);
    }
}
