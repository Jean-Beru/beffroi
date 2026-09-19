<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use DateTimeInterface;
use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\SigningKeyRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The operator's side of a rotation (architecture §3.3, §5.5): one command stages a key, time activates it.
 * The first key of a tenant is activated at once, nobody caches an empty JWK Set; so is a key the operator
 * asks for now, or one that replaces a compromised key.
 */
#[AsCommand(
    name: 'heidi:keys:rotate',
    description: 'Stage a new signing key, sealed by the configured KMS and published at once; it signs once the staging delay elapsed, or at once with --now; --compromised retires the previous key with no window.',
)]
final readonly class KeysRotateCommand
{
    public const string NAME = 'heidi:keys:rotate';

    public function __construct(
        private TenantProvider $tenants,
        private SigningKeyRepositoryInterface $keys,
        private SigningKeyRotator $rotator,
        private RequestContextFactory $contexts,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Option(description: 'The JWS algorithm the key signs with.')]
        SignatureAlgorithm $algorithm = SignatureAlgorithm::RS256,
        #[Option(description: 'Activate the key at once, without the staging delay: for an operator who knows every relying party is cold.')]
        bool $now = false,
        #[Option(description: 'The active key is compromised: the new key signs at once and the compromised one leaves the JWK Set with no window.')]
        bool $compromised = false,
    ): int {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }

        $previous = $this->keys->findActive($tenant, $algorithm);
        $context = $this->contexts->fromConsole(self::NAME);
        if ($previous === null) {
            $key = $this->rotator->rotate($tenant, $algorithm, $context, $compromised);
            self::describe($io, $tenant, $key);
            $io->note(sprintf('The tenant had no active %s key: nothing to wait for, the key is active at once.', $algorithm->value));
        } elseif ($compromised) {
            $key = $this->rotator->rotate($tenant, $algorithm, $context, compromised: true);
            self::describe($io, $tenant, $key);
            $io->warning(sprintf('The key "%s" was active and is retired at once: every token it signed is refused from now on.', $previous->kid));
        } elseif ($now) {
            $key = $this->rotator->rotate($tenant, $algorithm, $context);
            self::describe($io, $tenant, $key);
            // Read again: the repository may hand a fresh object on every read, and the rotation just dated this one.
            $retiring = $this->keys->find($tenant, $previous->kid) ?? $previous;
            $io->note(sprintf('The key "%s" was active and is now retiring: it stays in the JWK Set until %s, while the tokens it signed are alive.', $retiring->kid, $retiring->retirementDueAt?->format(DateTimeInterface::RFC3339) ?? '?'));
        } else {
            $key = $this->rotator->stage($tenant, $algorithm, $context);
            self::describe($io, $tenant, $key);
            $io->note(sprintf('The key "%s" signs until then; the scheduled step activates the new key at %s, "heidi:keys:activate %s" does it earlier.', $previous->kid, $key->activationDueAt->format(DateTimeInterface::RFC3339), $key->kid));
            $io->success(sprintf('The key "%s" is published for "%s" and signs from %s.', $key->kid, $tenant->slug, $key->activationDueAt->format(DateTimeInterface::RFC3339)));

            return Command::SUCCESS;
        }
        $io->success(sprintf('The key "%s" signs the tokens of "%s" from now on.', $key->kid, $tenant->slug));

        return Command::SUCCESS;
    }

    private static function describe(SymfonyStyle $io, Tenant $tenant, SigningKey $key): void
    {
        $io->definitionList(
            [
                'Key identifier' => $key->kid,
            ],
            [
                'Algorithm' => $key->algorithm->value,
            ],
            [
                'Status' => $key->status->value,
            ],
            [
                'Tenant' => $tenant->slug,
            ],
        );
    }
}
