<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Port\SigningKeyRepositoryInterface;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A signing key for the tenant, sealed by the KMS and active at once (architecture §3.3, §5.5); run twice, a rotation.
 */
#[AsCommand(
    name: 'heidi:keys:generate',
    description: 'Generate a signing key, seal it with the configured KMS and make it the active one.',
)]
final readonly class KeysGenerateCommand
{
    public function __construct(
        private TenantProvider $tenants,
        private SigningKeyRepositoryInterface $keys,
        private SigningKeyRotator $rotator,
        private ClockInterface $clock,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Option(description: 'The JWS algorithm the key signs with.')]
        SignatureAlgorithm $algorithm = SignatureAlgorithm::RS256,
    ): int {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }

        $previous = $this->keys->findActive($tenant, $algorithm);
        $key = $this->rotator->rotate($tenant, $algorithm, RequestContext::unknown($this->clock->now()));

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
        if ($previous !== null) {
            $io->note(sprintf('The key "%s" was active and is now retiring: it stays in the JWK Set while the tokens it signed are alive.', $previous->kid));
        }
        $io->success(sprintf('The key "%s" signs the tokens of "%s" from now on.', $key->kid, $tenant->slug));

        return Command::SUCCESS;
    }
}
