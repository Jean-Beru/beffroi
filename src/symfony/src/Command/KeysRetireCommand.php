<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use function count;
use DateTimeInterface;
use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Heidi\Core\Domain\Key\TenantKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\KeyNotFoundException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Exception\RetirementNotDueException;
use function sprintf;
use Symfony\Component\Console\Attribute\Argument;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The end of a retirement window by hand (architecture §3.3): every key past its date with --due, what the
 * scheduled step does; one key before its date with --force, and the trail says so.
 */
#[AsCommand(
    name: 'heidi:keys:retire',
    description: 'Take a retiring key out of the JWK Set: one key by its identifier, before its retirement date with --force; or every key past its date with --due.',
)]
final readonly class KeysRetireCommand
{
    public const string NAME = 'heidi:keys:retire';

    public function __construct(
        private TenantProvider $tenants,
        private TenantKeyRotator $rotator,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Argument(description: 'The identifier ("kid") of the retiring key, as heidi:keys:list shows it.')]
        ?string $kid = null,
        #[Option(description: 'Retire the key although what is bound to it may still arrive: after a compromise, or when everything it is bound to is known to have expired.')]
        bool $force = false,
        #[Option(description: 'Retire every key past its retirement date, and no other: what the scheduled step does.')]
        bool $due = false,
    ): int {
        if ($due === ($kid !== null)) {
            $io->error('Name the key to retire, or pass --due to retire every key past its retirement date; not both, not neither.');

            return Command::INVALID;
        }

        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }
        $context = $this->contexts->fromConsole(self::NAME);

        if ($kid === null) {
            $retired = $this->rotator->retireDue($tenant, $context);
            if ($retired === []) {
                $io->note(sprintf('No key of "%s" is past its retirement date.', $tenant->slug));

                return Command::SUCCESS;
            }
            $io->listing(array_map(static fn (TenantKey $key): string => sprintf('%s, due since %s', $key->kid, $key->retirementDueAt?->format(DateTimeInterface::RFC3339) ?? '?'), $retired));
            $io->success(sprintf('%d key(s) of "%s" left the JWK Set.', count($retired), $tenant->slug));

            return Command::SUCCESS;
        }

        try {
            $key = $this->rotator->retire($tenant, $kid, $context, $force);
        } catch (RetirementNotDueException $exception) {
            $io->error([$exception->getMessage(), 'Wait for the date, or pass --force if nothing bound to it can arrive any more.']);

            return Command::FAILURE;
        } catch (KeyNotFoundException|LogicException $exception) {
            $io->error($exception->getMessage());

            return Command::FAILURE;
        }

        return self::retired($io, $tenant, $key, $force);
    }

    private static function retired(SymfonyStyle $io, Tenant $tenant, TenantKey $key, bool $force): int
    {
        $io->definitionList(
            [
                'Key identifier' => $key->kid,
            ],
            [
                'Status' => $key->status->value,
            ],
            [
                'Retired at' => $key->retiredAt?->format(DateTimeInterface::RFC3339) ?? '?',
            ],
        );
        if ($force) {
            $io->warning(sprintf('The key "%s" left the JWK Set before its retirement date: what is bound to it is refused from now on.', $key->kid));
        }
        $io->success(sprintf('The key "%s" of "%s" left the JWK Set.', $key->kid, $tenant->slug));

        return Command::SUCCESS;
    }
}
