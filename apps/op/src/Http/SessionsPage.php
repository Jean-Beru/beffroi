<?php

declare(strict_types=1);

namespace App\Http;

use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\CanPageActiveSessionsInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of where a person is signed in (architecture §5.2): one line per session open in their name,
 * what each one proved, when it was opened, when it was last seen and from where. What is open is what the
 * store answers at this instant, never a list this page keeps.
 *
 * The session of the browser reading the page is named as such, because ending that one is not the same
 * act as ending another: it signs the reader out.
 */
final readonly class SessionsPage
{
    public function __construct(
        private CanPageActiveSessionsInterface $sessions,
        private ClockInterface $clock,
        private AskedPage $asked,
        private AskedPeriod $period,
        private InteractionPages $pages,
    ) {
    }

    public function render(AuthenticationSession $current): Response
    {
        $period = $this->period->asked($current->user);

        return $this->pages->render('account/sessions.html.twig', [
            'user' => $current->user,
            'sessions' => $this->sessions->pageOfActiveSessions($current->user, $this->clock->now(), $this->asked->asked(), $period),
            'period' => $period,
            'current' => $current->id->toString(),
        ]);
    }
}
