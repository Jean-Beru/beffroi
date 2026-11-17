<?php

declare(strict_types=1);

namespace App\Command;

use App\Http\EnrolmentLink;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Exception\EnrolmentTicketRefusedException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: self::NAME,
    description: 'Issue the link that lets a person pose a passkey, and print it.',
)]
final readonly class UserEnrolmentTicketCommand
{
    public const string NAME = 'beffroi:user:enrolment-ticket';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private EnrolmentTicketIssue $tickets,
        private RequestContextFactory $contexts,
        private EnrolmentLink $links,
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
                'Link' => $this->links->of($issued),
            ],
        );
        $io->success(sprintf(
            'The link is printed once and opens one enrolment; whoever issued it hands it over. Any link issued for "%s" before this one opens nothing any more.',
            $user->username,
        ));

        return Command::SUCCESS;
    }
}
