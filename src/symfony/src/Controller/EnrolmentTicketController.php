<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\PresentedEnrolmentTicket;
use Beffroi\Bundle\Http\WhatWasRefused;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The page where a person poses their first passkey without a session (architecture §5.2, issue #613):
 * reached from the URL an administrator handed them, it names the account it opens and holds the one
 * ceremony it is for.
 *
 * A ticket that opens nothing gets the refusal every page of this provider gets, in one flat sentence
 * whatever the reason (decision 0006): an identifier nothing answers, a wrong value, a ticket already
 * spent or out of time are the same answer with the same status.
 */
#[AsController]
final readonly class EnrolmentTicketController
{
    public const string ROUTE = 'beffroi_interaction_enrolment_ticket';

    /**
     * The one the page of a refused ticket explains.
     */
    public const string REFUSED = 'enrolment_ticket_refused';

    public function __construct(
        private PresentedEnrolmentTicket $tickets,
        private WhatWasRefused $refusals,
        private InteractionPages $pages,
    ) {
    }

    #[Route(
        '/enrol/{ticket}/{value}',
        name: self::ROUTE,
        requirements: [
            'ticket' => '[0-9a-fA-F-]{36}',
        ],
        methods: ['GET'],
    )]
    public function __invoke(Request $request): Response
    {
        $ticket = $this->tickets->of($request);
        if ($ticket === null) {
            return $this->pages->error(Response::HTTP_NOT_FOUND, self::REFUSED);
        }

        return $this->pages->render('enrolment_ticket.html.twig', [
            'user' => $ticket->user,
            'ticket' => $this->tickets->parameters($request),
            'error' => $this->refusals->take($request)?->code,
        ]);
    }
}
