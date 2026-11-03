<?php

declare(strict_types=1);

namespace App\Http;

use App\Http\Account\AccountSections;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Symfony\Component\HttpFoundation\Response;

/**
 * The home of the account (architecture §5.2): who this browser is signed in as and since when, and the
 * pages of the account, each saying what the account holds there. The pages are the ones wired
 * (AccountSections), never a list of this page's own.
 */
final readonly class AccountHomePage
{
    public function __construct(
        private AccountSections $sections,
        private InteractionPages $pages,
    ) {
    }

    public function render(AuthenticationSession $session): Response
    {
        return $this->pages->render('account/home.html.twig', [
            'user' => $session->user,
            'signed_in_since' => $session->establishedAt,
            'sections' => $this->sections->of($session->user),
        ]);
    }
}
