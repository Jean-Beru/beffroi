<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\AccountAccess;
use App\Http\Account\ReachedOnTheSessionAloneInterface;
use App\Http\ActsPage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * What happened to the account of the signed-in user (architecture §5.2, issues #454 and #571): what the
 * journal holds of their own acts, of the times somebody signed in as them and of the times somebody
 * tried.
 */
#[AsController]
final readonly class AccountActsController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_acts';

    public function __construct(
        private AccountAccess $account,
        private ActsPage $page,
    ) {
    }

    #[Route('/account/acts', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        return $this->page->render($session->user);
    }
}
