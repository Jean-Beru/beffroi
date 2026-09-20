<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Http\AccountAccess;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Credential\CredentialRevocation;
use Heidi\Core\Application\Totp\ActiveTotp;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

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
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private ActiveTotp $activeTotp,
        private CredentialRevocation $revocation,
        private InteractionPages $pages,
        private UrlGeneratorInterface $router,
    ) {
    }

    #[Route('/account/two-factor/revoke', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request, self::CSRF_TOKEN_ID);
        if ($session instanceof Response) {
            return $session;
        }
        $totp = $this->activeTotp->of($session->user) ?? throw new NotFoundHttpException('No authenticator app is set up.');
        $this->revocation->revoke($totp, $this->contexts->fromRequest($request));

        return $this->pages->redirect($this->router->generate(AccountTwoFactorController::ROUTE));
    }
}
