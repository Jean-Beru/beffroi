<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\Account\ReachedOnTheSessionAloneInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\SignInsPage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The recent sign-ins of the signed-in user (architecture §5.2, issue #454): what the journal holds of the
 * times somebody signed in as them, and of the times somebody tried.
 */
#[AsController]
final readonly class AccountSignInsController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_sign_ins';

    public function __construct(
        private AccountAccess $account,
        private SignInsPage $page,
    ) {
    }

    #[Route('/account/sign-ins', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        return $this->page->render($session->user);
    }
}
