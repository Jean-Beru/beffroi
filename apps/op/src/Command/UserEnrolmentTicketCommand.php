<?php

declare(strict_types=1);

namespace App\Command;

use App\Controller\EnrolmentTicketController;
use App\Http\PresentedEnrolmentTicket;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Exception\EnrolmentTicketRefusedException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The link is the origin of the issuer and the generated path, which already carries the path of the issuer.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Issue the link that lets a person pose their first passkey, and print it.',
)]
final readonly class UserEnrolmentTicketCommand
{
    public const string NAME = 'beffroi:user:enrolment-ticket';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private EnrolmentTicketIssue $tickets,
        private RequestContextFactory $contexts,
        private UrlGeneratorInterface $router,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the person, as "beffroi:user:show" names them.')]
        string $username,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }

        try {
            $issued = $this->tickets->issue($user, $this->contexts->fromConsole(self::NAME));
        } catch (EnrolmentTicketRefusedException $exception) {
            $io->error($exception->getMessage());

            return Command::INVALID;
        }

        $io->definitionList(
            [
                'Person' => $user->username,
            ],
            [
                'Opens until' => $issued->ticket->expiresAt->format('c'),
            ],
            [
                'Link' => $tenant->issuer->origin()
                    . $this->router->generate(
                        EnrolmentTicketController::ROUTE,
                        [
                            PresentedEnrolmentTicket::TICKET_PARAMETER => $issued->ticket->id->toRfc4122(),
                            PresentedEnrolmentTicket::VALUE_PARAMETER => $issued->value,
                        ],
                        UrlGeneratorInterface::ABSOLUTE_PATH,
                    ),
            ],
        );
        $io->success(sprintf(
            'The link is printed once and opens one enrolment; whoever issued it hands it over. Any link issued for "%s" before this one opens nothing any more.',
            $user->username,
        ));

        return Command::SUCCESS;
    }
}
