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
 * The ticket the identifier and the value of an enrolment URL open, or nothing, never why (decision 0006).
 * A malformed identifier pays no hash, there being no ticket to tell it apart from.
 */
final readonly class PresentedEnrolmentTicket
{
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
