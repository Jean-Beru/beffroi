<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\ConsentRepositoryInterface;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Heidi\Core\Port\UserRepositoryInterface;

/**
 * Takes back what a user agreed to let a client obtain (architecture §4.3). A consent is remembered so
 * that a user who agreed once is not asked again; taking it back is how they change their mind, and the
 * next authorization request of that client asks them afresh. The tokens already issued are not touched:
 * a consent says what may be granted, not what was.
 */
#[AsCommand(
    name: self::NAME,
    description: 'Take back the consent a user gave a client; the next authorization request asks again.',
)]
final readonly class UserRevokeConsentCommand
{
    public const string NAME = 'heidi:user:revoke-consent';

    public function __construct(
        private TenantProvider $tenants,
        private UserRepositoryInterface $users,
        private ClientRepositoryInterface $clients,
        private ConsentRepositoryInterface $consents,
        private ClockInterface $clock,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The username of the user.')]
        string $username,
        #[Argument(description: 'The identifier of the client the consent was given to.')]
        string $clientId,
    ): int {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }
        $user = $this->users->findByUsername($tenant, $username);
        if ($user === null) {
            $io->error(sprintf('No user "%s" is registered with this tenant.', $username));

            return Command::INVALID;
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
        $consent->revoke($this->clock->now());
        $this->consents->save($consent);
        $io->success(sprintf('"%s" has taken back what "%s" was granted; the next authorization request asks again.', $username, $clientId));

        return Command::SUCCESS;
    }
}
