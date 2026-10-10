<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of the recent sign-ins of a person (architecture §5.2, issue #454): when somebody signed in as
 * them, and when somebody tried and did not, each with what the request carried of where it came from.
 *
 * **The failures are on it and not only the successes**, because that is what the page is for: a person
 * who reads nothing but their own successful sign-ins learns nothing they did not already know, where a
 * line they do not recognise is the whole point of showing them a journal at all.
 *
 * Which acts are a sign-in is this page's question, so the page names them, by the constants the events
 * carry (ActsOfAPersonInterface). It reads the journal and holds no list of its own.
 */
final readonly class SignInsPage
{
    public function __construct(
        private CanPageActsOfAPersonInterface $acts,
        private AskedPage $asked,
        private InteractionPages $pages,
    ) {
    }

    public function render(User $user): Response
    {
        return $this->pages->render('account/sign_ins.html.twig', [
            'user' => $user,
            'acts' => $this->acts->pageOfActs($user, [UserAuthenticated::NAME, AuthenticationFailed::NAME], $this->asked->asked()),
            'succeeded' => UserAuthenticated::NAME,
        ]);
    }
}
