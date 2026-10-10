<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CanPageChangesOfAPersonInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of what a person has changed of their own record (issue #482, architecture §5.2): one line per
 * change, what it said before, what it says now and when it was made.
 *
 * **A page of its own and not a panel of the profile**, because it is the one thing of that record that
 * grows without end: the profile says what is held now, in as many lines as there are claims, where this
 * is read in pages and over the stretch of time the reader asks for.
 */
final readonly class ClaimChangesPage
{
    public function __construct(
        private CanPageChangesOfAPersonInterface $changes,
        private AskedPage $page,
        private AskedPeriod $period,
        private InteractionPages $pages,
    ) {
    }

    public function render(User $user): Response
    {
        $period = $this->period->asked($user);

        return $this->pages->render('account/changes.html.twig', [
            'user' => $user,
            'changes' => $this->changes->pageOfChanges($user, $this->page->asked(), $period),
            'period' => $period,
        ]);
    }
}
