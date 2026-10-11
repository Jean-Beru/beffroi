<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\ActsOfAnAccount;
use Beffroi\Core\Domain\Journal\JournalQuestion;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of what happened to the account of a person (architecture §5.2, issues #454 and #571): when
 * somebody signed in as them and with what, when somebody tried and did not, what signed out, what changed
 * of the means of signing in, and what they did of their own record.
 *
 * **The refusals are on it and not only the successes**, because that is what the page is for: a person
 * who reads nothing but their own successful sign-ins learns nothing they did not already know, where a
 * line they do not recognise is the whole point of showing them a journal at all.
 *
 * **Each act says what it is**, by the name the event gave itself, read from the catalogue; the page holds
 * no outcome of its own, a refusal being an act like the rest. Which acts are what happened to an account
 * is the journal's to say and not a list this page keeps (ActsOfAnAccount), because the command that reads
 * the same journal over a period asks the same question of it.
 */
final readonly class ActsPage
{
    public function __construct(
        private CanPageActsOfAPersonInterface $acts,
        private AskedPage $asked,
        private AskedPeriod $period,
        private InteractionPages $pages,
    ) {
    }

    public function render(User $user): Response
    {
        $period = $this->period->asked($user);

        return $this->pages->render('account/acts.html.twig', [
            'user' => $user,
            'acts' => $this->acts->pageOfActs(
                $user,
                new JournalQuestion(ActsOfAnAccount::NAMES, period: $period),
                $this->asked->asked(),
            ),
            'period' => $period,
        ]);
    }
}
