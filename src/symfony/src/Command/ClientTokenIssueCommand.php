<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use DateInterval;
use Heidi\Oidc\Application\Client\Registration\InitialAccessTokenIssuance;
use Heidi\Oidc\Exception\InvalidArgumentException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use function trim;

/**
 * A tenant hands somebody the right to register a client with it (RFC 7591 §1.2, decision 0009). It is
 * the way in to the controlled mode: without a token nobody registers, so a tenant that offers that mode
 * and has issued nothing authorises nobody.
 *
 * **The value is printed here and nowhere else, ever.** The row holds its digest, as every value this
 * provider draws is held, so nothing reads it back: whoever issued it hands it to the team that
 * integrates, and a tenant that lost one issues another and revokes this one.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Issue an initial access token for the tenant; the value is printed once and never again.',
)]
final readonly class ClientTokenIssueCommand
{
    public const string NAME = 'heidi:client:token:issue';

    /**
     * What a token is worth and for how long when the command line says neither: one client, thirty days.
     * A token worth more or living longer is a token asked for, never a default.
     */
    public const int DEFAULT_REGISTRATIONS = 1;

    public const int DEFAULT_DAYS = 30;

    public function __construct(
        private ConfiguredTenant $tenant,
        private InitialAccessTokenIssuance $issuance,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'What the tenant calls this token, to know later which integration it was for.')]
        string $name,
        #[Option(description: 'How many clients it may register.')]
        int $registrations = self::DEFAULT_REGISTRATIONS,
        #[Option(description: 'How many days it is worth anything, counted from now.')]
        int $days = self::DEFAULT_DAYS,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        if ($days < 1) {
            $io->error('An initial access token is worth something for a day at least.');

            return Command::INVALID;
        }

        try {
            $issued = $this->issuance->issue(
                $tenant,
                trim($name),
                $registrations,
                new DateInterval(sprintf('P%dD', $days)),
            );
        } catch (InvalidArgumentException $exception) {
            $io->error($exception->getMessage());

            return Command::INVALID;
        }

        $io->definitionList(
            [
                'Id' => $issued->token->id->toRfc4122(),
            ],
            [
                'Name' => $issued->token->name,
            ],
            [
                'Registrations' => (string) $issued->token->registrationsAllowed,
            ],
            [
                'Expires' => $issued->token->expiresAt->format('Y-m-d H:i:s'),
            ],
        );
        $io->success('The initial access token is issued. It is printed once, here, and this provider cannot show it again.');
        $io->writeln($issued->value);

        return Command::SUCCESS;
    }
}
