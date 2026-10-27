<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Bundle\Controller\EnrolmentTicketController;
use Beffroi\Bundle\Http\PresentedEnrolmentTicket;
use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Exception\EnrolmentTicketRefusedException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The link that lets one person pose their first passkey without a session (issue #613), for a person a
 * tenant has just created and who has nothing to sign in with: on a tenant that signs its users in by
 * passkey, there is no password to give them (decision 0025).
 *
 * It prints the URL once, the row holding a hash of what it carries: whoever issued it hands it over, and
 * a link lost is a link issued again, which takes the first one away. It is the use case a screen of the
 * console will press (epic #194); what it does, a command does.
 *
 * The URL is the route of the page under the origin of the issuer, as RouterEndpointLocator locates the
 * endpoints: the path the router generates already carries the prefix the routes are mounted under, which
 * is the path of the issuer, so the issuer itself in front of it would say that path twice (issue #841).
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
