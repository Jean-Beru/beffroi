<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\PasskeyOptionsStore;
use Beffroi\Bundle\Http\PresentedEnrolmentTicket;
use Beffroi\Core\Application\Passkey\PasskeyEnrolment;
use Beffroi\Core\Bridge\Webauthn\WebauthnCeremonies;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The options a browser on the page of an enrolment ticket creates a passkey with (WebAuthn Level 3 §7.1,
 * issue #613): the ones the enrolment of the core draws for the person the ticket names, kept in the
 * session of that browser until the attestation comes back.
 *
 * It is the counterpart of the options of the page of the account, for a browser that holds no session:
 * what stands in for one is the ticket, read at every request of this enrolment and never trusted from
 * the one before.
 */
#[AsController]
final readonly class EnrolmentTicketOptionsController
{
    public const string ROUTE = 'beffroi_interaction_enrolment_ticket_options';

    public function __construct(
        private PresentedEnrolmentTicket $tickets,
        private PasskeyEnrolment $enrolment,
        private WebauthnCeremonies $ceremonies,
        private PasskeyOptionsStore $options,
    ) {
    }

    #[Route(
        '/enrol/{ticket}/{value}/options',
        name: self::ROUTE,
        requirements: [
            'ticket' => '[0-9a-fA-F-]{36}',
        ],
        methods: ['POST'],
    )]
    public function __invoke(Request $request): Response
    {
        $ticket = $this->tickets->of($request);
        if ($ticket === null) {
            return new JsonResponse(
                [
                    'error' => EnrolmentTicketController::REFUSED,
                ],
                Response::HTTP_NOT_FOUND,
                InteractionPages::HEADERS,
            );
        }
        $options = $this->enrolment->begin($ticket->user);
        $this->options->storeCreation($request->getSession(), $ticket->user->id, $options);

        return new Response($this->ceremonies->optionsToJson($options), Response::HTTP_OK, [
            'Content-Type' => 'application/json',
            ...InteractionPages::HEADERS,
        ]);
    }
}
