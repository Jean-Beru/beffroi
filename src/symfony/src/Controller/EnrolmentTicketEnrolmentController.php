<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Http\FormToken;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\PasskeyOptionsStore;
use Beffroi\Bundle\Http\PresentedEnrolmentTicket;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Bundle\Http\WhatWasRefused;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketRedemption;
use Beffroi\Core\Application\Passkey\PasskeyEnrolment;
use Beffroi\Core\Exception\CredentialEnrolmentFailedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The attestation of a first passkey, posted by the page of an enrolment ticket (issue #613): verified by
 * the enrolment of the core against the options this browser was given for the person the ticket names,
 * then the ticket is spent and the browser is sent to sign in with what it just posed.
 *
 * **The ticket is spent once the passkey is in the rows and never before**: a ceremony the browser could
 * not finish, or one the model refused, leaves the person their link.
 */
#[AsController]
final readonly class EnrolmentTicketEnrolmentController
{
    public const string ROUTE = 'beffroi_interaction_enrolment_ticket_enrol';

    public const string CSRF_TOKEN_ID = 'beffroi_enrolment_ticket';

    public const string ATTESTATION_PARAMETER = '_passkey';

    public const string NAME_PARAMETER = 'name';

    public const string NO_CEREMONY = 'no_ceremony';

    public const string REFUSED = 'refused';

    public function __construct(
        private PresentedEnrolmentTicket $tickets,
        private EnrolmentTicketRedemption $redemption,
        private PasskeyEnrolment $enrolment,
        private PasskeyOptionsStore $options,
        private FormToken $formTokens,
        private WhatWasRefused $refusals,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
    ) {
    }

    #[Route(
        '/enrol/{ticket}/{value}',
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
            return $this->pages->error(Response::HTTP_NOT_FOUND, EnrolmentTicketController::REFUSED);
        }
        $refusal = $this->formTokens->refusal($request->request->getString(FormToken::PARAMETER), self::CSRF_TOKEN_ID);
        if ($refusal !== null) {
            return $refusal;
        }
        $attestation = $request->request->getString(self::ATTESTATION_PARAMETER);
        $options = $this->options->takeCreation($request->getSession(), $ticket->user->id);
        if ($attestation === '' || $options === null) {
            return $this->refused($request, self::NO_CEREMONY);
        }
        try {
            $this->enrolment->complete(
                $ticket->user,
                $request->request->getString(self::NAME_PARAMETER),
                $options,
                $attestation,
                $this->contexts->fromRequest($request),
            );
        } catch (CredentialEnrolmentFailedException) {
            return $this->refused($request, self::REFUSED);
        }
        $this->redemption->spend($ticket);

        // the account of that person, which sends a browser that holds no session to the login page where
        // the passkey it has just posed signs them in
        return $this->pages->afterTheForm(AccountController::ROUTE);
    }

    private function refused(Request $request, string $code): Response
    {
        $this->refusals->keep($request, $code);

        return $this->pages->afterTheForm(EnrolmentTicketController::ROUTE, $this->tickets->parameters($request));
    }
}
