<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use DateTimeInterface;
use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Exception\KeyNotFoundException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Port\SigningKeyRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The second step of a rotation by hand (architecture §3.3): what the scheduled step does once the staging
 * delay elapsed, for an operator who knows every relying party has seen the key.
 */
#[AsCommand(
    name: 'heidi:keys:activate',
    description: 'Make a staged signing key the active one before its staging delay elapsed; the key that signed starts retiring.',
)]
final readonly class KeysActivateCommand
{
    public const string NAME = 'heidi:keys:activate';

    public function __construct(
        private TenantProvider $tenants,
        private SigningKeyRepositoryInterface $keys,
        private SigningKeyRotator $rotator,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The identifier ("kid") of the staged key, as heidi:keys:list shows it.')]
        string $kid,
    ): int {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }

        $staged = $this->keys->find($tenant, $kid);
        $previous = $staged === null ? null : $this->keys->findActive($tenant, $staged->algorithm);

        try {
            $key = $this->rotator->activate($tenant, $kid, $this->contexts->fromConsole(self::NAME));
        } catch (KeyNotFoundException|LogicException $exception) {
            $io->error($exception->getMessage());

            return Command::FAILURE;
        }

        $io->definitionList(
            [
                'Key identifier' => $key->kid,
            ],
            [
                'Algorithm' => $key->algorithm->name(),
            ],
            [
                'Status' => $key->status->value,
            ],
            [
                'Activated at' => $key->activatedAt?->format(DateTimeInterface::RFC3339) ?? '?',
            ],
        );
        if ($previous !== null) {
            // Read again: the repository may hand a fresh object on every read, and the rotation just dated this one.
            $retiring = $this->keys->find($tenant, $previous->kid) ?? $previous;
            $io->note(sprintf('The key "%s" was active and is now retiring: it stays in the JWK Set until %s, while the tokens it signed are alive.', $retiring->kid, $retiring->retirementDueAt?->format(DateTimeInterface::RFC3339) ?? '?'));
        }
        $io->success(sprintf('The key "%s" signs the tokens of "%s" from now on.', $key->kid, $tenant->slug));

        return Command::SUCCESS;
    }
}
