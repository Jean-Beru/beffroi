<?php

declare(strict_types=1);

namespace App\Controller;

use App\Http\Account\ReachedOnTheSessionAloneInterface;
use App\Http\AccountAccess;
use App\Http\ClaimChangesPage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * What the signed-in person has changed of their own record (issue #482): a page under the page of their
 * information, read in pages and over the stretch of time they ask for.
 */
#[AsController]
final readonly class AccountClaimChangesController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_profile_changes';

    public function __construct(
        private AccountAccess $account,
        private ClaimChangesPage $page,
    ) {
    }

    #[Route('/account/profile/changes', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        return $this->page->render($session->user);
    }
}
