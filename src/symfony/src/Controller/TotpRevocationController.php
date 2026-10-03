<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Credential\CredentialRevocation;
use Beffroi\Core\Application\Totp\ActiveTotp;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The authenticator app of the signed-in user removed from the page of the account (architecture §5.2):
 * the TOTP is revoked, its row stays, and the password alone signs the user in again. Without an active
 * one there is nothing to remove. What becomes of the sessions it completed is the caller's policy
 * (§3.4): this one leaves them.
 */
#[AsController]
final readonly class TotpRevocationController
{
    public const string ROUTE = 'beffroi_interaction_account_two_factor_revoke';

    public const string CSRF_TOKEN_ID = 'beffroi_two_factor_revoke';

    public function __construct(
        private AccountAccess $account,
        private RequestContextFactory $contexts,
        private ActiveTotp $activeTotp,
        private CredentialRevocation $revocation,
        private InteractionPages $pages,
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

        return $this->pages->afterTheForm(AccountTwoFactorController::ROUTE);
    }
}
