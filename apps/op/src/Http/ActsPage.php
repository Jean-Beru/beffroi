<?php

declare(strict_types=1);

namespace App\Http;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\ActsOfAnAccount;
use Beffroi\Core\Domain\Journal\JournalQuestion;
use Beffroi\Core\Port\CanPageActsOfAPersonInterface;
use Symfony\Component\HttpFoundation\Response;

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
