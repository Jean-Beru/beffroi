<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Command;

use Beffroi\Bundle\Http\RequestContextFactory;
use Beffroi\Core\Application\Key\TenantKeyRotator;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Port\KeyAlgorithmsInterface;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * A key for the tenant, sealed by the KMS and active at once (architecture §3.3, §5.5): what
 * "beffroi:keys:rotate --now" does, kept under this name for the first key of a tenant; run twice, a
 * rotation without a staging window. The algorithm names what the key is for: a JWS algorithm gives a key
 * that signs, a JWE key management algorithm a key a client encrypts to.
 */
#[AsCommand(
    name: 'beffroi:keys:generate',
    description: 'Generate a key, seal it with the configured KMS and make it the active one of its algorithm at once; "beffroi:keys:rotate" is the rotation without an outage.',
)]
final readonly class KeysGenerateCommand
{
    public const string NAME = 'beffroi:keys:generate';

    public function __construct(
        private ConfiguredTenant $tenant,
        private TenantKeyRepositoryInterface $keys,
        private TenantKeyRotator $rotator,
        private RequestContextFactory $contexts,
        private SignatureAlgorithmsInterface $signatureAlgorithms,
        private KeyAlgorithmsInterface $algorithms,
    ) {
    }

    /**
     * What both this command and "beffroi:keys:rotate" offer, said once: the wiring is the one source of
     * truth over the algorithms, so the option describes it the same way wherever it is offered.
     */
    public const string ALGORITHM_OPTION = 'The algorithm the key pair is generated for, among those the provider is wired with: a JWS algorithm for a key that signs, a JWE key management one for a key clients encrypt to. The default signature algorithm when none is named.';

    public function __invoke(
        SymfonyStyle $io,
        #[Option(description: self::ALGORITHM_OPTION)]
        ?string $algorithm = null,
    ): int {
        $tenant = $this->tenant->orTold($io);
        if ($tenant === null) {
            return Command::FAILURE;
        }

        try {
            $generatedFor = $algorithm === null ? $this->signatureAlgorithms->defaultAlgorithm() : $this->algorithms->named($algorithm);
        } catch (UnsupportedAlgorithmException $exception) {
            $io->error($exception->getMessage());

            return Command::FAILURE;
        }

        $previous = $this->keys->findActive($tenant, $generatedFor);
        $key = $this->rotator->rotate($tenant, $generatedFor, $this->contexts->fromConsole(self::NAME));

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
        if ($previous !== null) {
            $io->note(sprintf(
                'The key "%s" was active and is now retiring: it stays in the JWK Set while what is bound to it may still arrive.',
                $previous->kid,
            ));
        }
        $io->success(sprintf('The key "%s" is the active %s key of "%s" from now on.', $key->kid, $key->algorithm->name(), $tenant->slug));

        return Command::SUCCESS;
    }
}
