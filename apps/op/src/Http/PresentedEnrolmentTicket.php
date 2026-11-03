<?php

declare(strict_types=1);

namespace App\Http;

use App\Doctrine\TenantProvider;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketRedemption;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Exception\EnrolmentTicketRefusedException;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Uid\Uuid;

/**
 * The ticket a URL of the enrolment presents (issue #613): the identifier and the value, read from the
 * route, and the ticket the core says they open. The three pages of that enrolment ask here, as the pages
 * of an account ask AccountAccess, so what makes a ticket open something is read in one place.
 *
 * What it answers is nothing or a ticket: which of the reasons it was, an identifier nothing answers, a
 * wrong value, a ticket spent, out of time or of a person who cannot sign in, is the core's business and
 * is not told (decision 0006). A malformed identifier is not a ticket at all and no hash is paid for it,
 * there being no ticket to tell it apart from.
 */
final readonly class PresentedEnrolmentTicket
{
    /**
     * The identifier of the ticket in the route, and the value beside it.
     */
    public const string TICKET_PARAMETER = 'ticket';

    public const string VALUE_PARAMETER = 'value';

    public function __construct(
        private TenantProvider $tenants,
        private EnrolmentTicketRedemption $redemption,
    ) {
    }

    public function of(Request $request): ?EnrolmentTicket
    {
        $id = $request->attributes->getString(self::TICKET_PARAMETER);
        if (! Uuid::isValid($id)) {
            return null;
        }

        try {
            return $this->redemption->redeem(
                $this->tenants->provide(),
                Uuid::fromString($id),
                $request->attributes->getString(self::VALUE_PARAMETER),
            );
        } catch (EnrolmentTicketRefusedException) {
            return null;
        }
    }

    /**
     * What the pages of that enrolment carry in their URLs, so that a form of one posts to the next.
     *
     * @return array<string, string>
     */
    public function parameters(Request $request): array
    {
        return [
            self::TICKET_PARAMETER => $request->attributes->getString(self::TICKET_PARAMETER),
            self::VALUE_PARAMETER => $request->attributes->getString(self::VALUE_PARAMETER),
        ];
    }
}
