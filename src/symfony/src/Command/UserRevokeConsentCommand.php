<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Oidc\Application\Consent\ConsentRevocation;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\ConsentRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Takes back what a user agreed to let a client obtain (architecture §4.3), for an administrator who is
 * asked to do it for somebody, the page of the account being where that somebody does it themselves. A
 * consent is remembered so that a user who agreed once is not asked again; taking it back is how they
 * change their mind, and the next authorization request of that client asks them afresh.
 *
 * What was issued under that consent goes with it, here as on the page: one consent taken back is one
 * fact however it was asked for, and the rule is ConsentRevocation's, not this command's.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Take back the consent a user gave a client, and the access it holds; the next authorization request asks again.',
)]
final readonly class UserRevokeConsentCommand
{
    public const string NAME = 'beffroi:user:revoke-consent';

    public function __construct(
        private ConfiguredTenant $tenant,
        private NamedUser $namedUsers,
        private ClientRepositoryInterface $clients,
        private ConsentRepositoryInterface $consents,
        private ConsentRevocation $revocation,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user.')]
        string $username,
        #[Argument(description: 'The identifier of the client the consent was given to.')]
        string $clientId,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }
        $user = $this->namedUsers->orTold($io, $tenant, $username);
        if ($user === null) {
            return Command::FAILURE;
        }
        $client = $this->clients->findByClientId($tenant, $clientId);
        if ($client === null) {
            $io->error(sprintf('No client "%s" is registered with this tenant.', $clientId));

            return Command::INVALID;
        }
        $consent = $this->consents->findActive($user, $client);
        if ($consent === null) {
            $io->note(sprintf('"%s" has granted nothing to "%s"; there is nothing to take back.', $username, $clientId));

            return Command::SUCCESS;
        }
        $this->revocation->revoke($consent, $this->contexts->fromConsole(self::NAME));
        $io->success(sprintf(
            '"%s" has taken back what "%s" was granted, and what it was issued under it; the next authorization request asks again.',
            $username,
            $clientId,
        ));

        return Command::SUCCESS;
    }
}
