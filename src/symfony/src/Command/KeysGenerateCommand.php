<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Key\SigningKeyRotator;
use Heidi\Core\Exception\UnsupportedAlgorithmException;
use Heidi\Core\Port\SignatureAlgorithmsInterface;
use Heidi\Core\Port\SigningKeyRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A signing key for the tenant, sealed by the KMS and active at once (architecture §3.3, §5.5): what
 * "heidi:keys:rotate --now" does, kept under this name for the first key of a tenant; run twice, a
 * rotation without a staging window.
 */
#[AsCommand(
    name: 'heidi:keys:generate',
    description: 'Generate a signing key, seal it with the configured KMS and make it the active one at once; "heidi:keys:rotate" is the rotation without an outage.',
)]
final readonly class KeysGenerateCommand
{
    public const string NAME = 'heidi:keys:generate';

    public function __construct(
        private TenantProvider $tenants,
        private SigningKeyRepositoryInterface $keys,
        private SigningKeyRotator $rotator,
        private RequestContextFactory $contexts,
        private SignatureAlgorithmsInterface $algorithms,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Option(description: 'The JWS algorithm the key signs with, among those the provider is wired with; its default when none is named.')]
        ?string $algorithm = null,
    ): int {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }

        try {
            $signsWith = $algorithm === null ? $this->algorithms->defaultAlgorithm() : $this->algorithms->named($algorithm);
        } catch (UnsupportedAlgorithmException $exception) {
            $io->error($exception->getMessage());

            return Command::FAILURE;
        }

        $previous = $this->keys->findActive($tenant, $signsWith);
        $key = $this->rotator->rotate($tenant, $signsWith, $this->contexts->fromConsole(self::NAME));

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
