<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use DateTimeInterface;
use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Key\TenantKeyRotator;
use Heidi\Core\Domain\Key\TenantKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\UnsupportedAlgorithmException;
use Heidi\Core\Port\KeyAlgorithmsInterface;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Core\Port\TenantKeyRepositoryInterface;
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
    description: 'Stage a new key, sealed by the configured KMS and published at once; it takes over once the staging delay elapsed, or at once with --now; --compromised retires the previous key with no window.',
)]
final readonly class KeysRotateCommand
{
    public const string NAME = 'heidi:keys:rotate';

    public function __construct(
        private TenantProvider $tenants,
        private TenantKeyRepositoryInterface $keys,
        private TenantKeyRotator $rotator,
        private RequestContextFactory $contexts,
        private SignatureAlgorithmsInterface $signatureAlgorithms,
        private KeyAlgorithmsInterface $algorithms,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Option(
            description: 'The algorithm the key pair is generated for, among those the provider is wired with: a JWS algorithm for a key that signs, a JWE key management one for a key clients encrypt to. The default signature algorithm when none is named.',
        )]
        ?string $algorithm = null,
        #[Option(
            description: 'Activate the key at once, without the staging delay: a relying party whose JWK Set copy is younger than 60 s refuses the new tokens, or encrypts to the old key, until it is that old (oidc_login refetches once then); for an operator who knows every relying party is cold.',
        )]
        bool $now = false,
        #[Option(description: 'The active key is compromised: the new key takes over at once and the compromised one leaves the JWK Set with no window.')]
        bool $compromised = false,
    ): int {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }

        try {
            $rotatedFor = $algorithm === null ? $this->signatureAlgorithms->defaultAlgorithm() : $this->algorithms->named($algorithm);
        } catch (UnsupportedAlgorithmException $exception) {
            $io->error($exception->getMessage());

            return Command::FAILURE;
        }

        $previous = $this->keys->findActive($tenant, $rotatedFor);
        $context = $this->contexts->fromConsole(self::NAME);
        if ($previous === null) {
            $key = $this->rotator->rotate($tenant, $rotatedFor, $context, $compromised);
            self::describe($io, $tenant, $key);
            $io->note(sprintf('The tenant had no active %s key: nothing to wait for, the key is active at once.', $rotatedFor->name()));
        } elseif ($compromised) {
            $key = $this->rotator->rotate($tenant, $rotatedFor, $context, compromised: true);
            self::describe($io, $tenant, $key);
            $io->warning(sprintf(
                'The key "%s" was active and is retired at once: it leaves the JWK Set and nothing bound to it is honoured from now on.',
                $previous->kid,
            ));
        } elseif ($now) {
            $key = $this->rotator->rotate($tenant, $rotatedFor, $context);
            self::describe($io, $tenant, $key);
            // Read again: the repository may hand a fresh object on every read, and the rotation just dated this one.
            $retiring = $this->keys->find($tenant, $previous->kid) ?? $previous;
            $io->note(sprintf(
                'The key "%s" was active and is now retiring: it stays in the JWK Set until %s, while what is bound to it may still arrive.',
                $retiring->kid,
                $retiring->retirementDueAt?->format(DateTimeInterface::RFC3339) ?? '?',
            ));
        } else {
            $key = $this->rotator->stage($tenant, $rotatedFor, $context);
            self::describe($io, $tenant, $key);
            $io->note(sprintf(
                'The key "%s" is the active one until then; the scheduled step activates the new key at %s, "heidi:keys:activate %s" does it earlier.',
                $previous->kid,
                $key->activationDueAt->format(DateTimeInterface::RFC3339),
                $key->kid,
            ));
            $io->success(sprintf(
                'The key "%s" is published for "%s" and takes over at %s.',
                $key->kid,
                $tenant->slug,
                $key->activationDueAt->format(DateTimeInterface::RFC3339),
            ));

            return Command::SUCCESS;
        }
        $io->success(sprintf('The key "%s" is the active %s key of "%s" from now on.', $key->kid, $key->algorithm->name(), $tenant->slug));

        return Command::SUCCESS;
    }

    private static function describe(SymfonyStyle $io, Tenant $tenant, TenantKey $key): void
    {
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
                'Tenant' => $tenant->slug,
            ],
        );
    }
}
