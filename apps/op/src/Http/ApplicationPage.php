<?php

declare(strict_types=1);

namespace App\Http;

use App\Account\ApplicationHoldings;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of one application (issue #451, architecture §4.3, §5.2): what this person agreed to let it
 * obtain and when, what of it the application can still renew at this instant, and what it has asked that
 * is waiting for an answer of theirs. The button that takes it back is the one of the list, and what it
 * revokes is the consent and everything issued under it, in one act (ConsentRevocation).
 *
 * What it shows is read by ApplicationHoldings, which "beffroi:user:applications" asks the same question
 * of: a page and a command say the same thing of the same person because one reading answers both.
 */
final readonly class ApplicationPage
{
    public function __construct(
        private ApplicationHoldings $holdings,
        private InteractionPages $pages,
    ) {
    }

    public function render(User $user, Consent $consent): Response
    {
        return $this->pages->render('account/application.html.twig', [
            'user' => $user,
            'holding' => $this->holdings->of($user, $consent),
        ]);
    }
}
