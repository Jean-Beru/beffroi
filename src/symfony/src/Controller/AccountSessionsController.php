<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\Account\ReachedOnTheSessionAloneInterface;
use Beffroi\Bundle\Http\AccountAccess;
use Beffroi\Bundle\Http\SessionsPage;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Where the signed-in user is signed in (architecture §5.2): the sessions open in their name, and the
 * button that ends one. A browser without a session of the core is told to sign in first.
 */
#[AsController]
final readonly class AccountSessionsController implements ReachedOnTheSessionAloneInterface
{
    public const string ROUTE = 'beffroi_interaction_account_sessions';

    public function __construct(
        private AccountAccess $account,
        private SessionsPage $page,
    ) {
    }

    #[Route('/account/sessions', name: self::ROUTE, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        $session = $this->account->granted($request);
        if ($session instanceof Response) {
            return $session;
        }

        return $this->page->render($session);
    }
}
