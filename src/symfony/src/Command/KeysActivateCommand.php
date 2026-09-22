<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use DateTimeInterface;
use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Heidi\Core\Exception\KeyNotFoundException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Port\TenantKeyRepositoryInterface;
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
    description: 'Make a staged key the active one of its algorithm before its staging delay elapsed; the key it takes over from starts retiring.',
)]
final readonly class KeysActivateCommand
{
    public const string NAME = 'heidi:keys:activate';

    public function __construct(
        private TenantProvider $tenants,
        private TenantKeyRepositoryInterface $keys,
        private TenantKeyRotator $rotator,
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
                'Use' => $key->algorithm->keyUse()->value,
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
            $io->note(sprintf(
                'The key "%s" was active and is now retiring: it stays in the JWK Set until %s, while what is bound to it may still arrive.',
                $retiring->kid,
                $retiring->retirementDueAt?->format(DateTimeInterface::RFC3339) ?? '?',
            ));
        }
        $io->success(sprintf('The key "%s" is the active %s key of "%s" from now on.', $key->kid, $key->algorithm->name(), $tenant->slug));

        return Command::SUCCESS;
    }
}
