<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Credential\CredentialRevocation;
use Heidi\Core\Application\Totp\ActiveTotp;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * The authenticator app of the signed-in user removed from the page of the account (architecture §5.2):
 * the TOTP is revoked, its row stays, and the password alone signs the user in again. Without an active
 * one there is nothing to remove. What becomes of the sessions it completed is the caller's policy
 * (§3.4): this one leaves them.
 */
#[AsController]
final readonly class TotpRevocationController
{
    public const string ROUTE = 'heidi_interaction_account_two_factor_revoke';

    public const string CSRF_TOKEN_ID = 'heidi_two_factor_revoke';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private ActiveTotp $activeTotp,
        private CredentialRevocation $revocation,
        private CsrfTokenManagerInterface $csrf,
        private InteractionPages $pages,
        private UrlGeneratorInterface $router,
    ) {
    }

    #[Route('/account/two-factor/revoke', name: self::ROUTE, methods: ['POST'])]
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
        $totp = $this->activeTotp->of($session->user) ?? throw new NotFoundHttpException('No authenticator app is set up.');
        $this->revocation->revoke($totp, $this->contexts->fromRequest($request));

        return $this->pages->redirect($this->router->generate(AccountTwoFactorController::ROUTE));
    }
}
