<?php

declare(strict_types=1);

namespace App\Http;

use App\Controller\EnrolmentTicketController;
use Beffroi\Core\Domain\Enrolment\IssuedEnrolmentTicket;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The link of an enrolment ticket: the origin of the issuer of its tenant and the path of the page that opens it, which
 * already carries the path of the issuer. Written by the routes of the provider, which a process of the administration
 * API does not serve.
 */
final readonly class EnrolmentLink
{
    public function __construct(
        private UrlGeneratorInterface $router,
    ) {
    }

    public function of(IssuedEnrolmentTicket $issued): string
    {
        return (
            $issued->ticket->tenant->issuer->origin()
            . $this->router->generate(
                EnrolmentTicketController::ROUTE,
                [
                    PresentedEnrolmentTicket::TICKET_PARAMETER => $issued->ticket->id->toRfc4122(),
                    PresentedEnrolmentTicket::VALUE_PARAMETER => $issued->value,
                ],
                UrlGeneratorInterface::ABSOLUTE_PATH,
            )
        );
    }
}
