<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use DateTimeImmutable;
use DateTimeInterface;
use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Core\Domain\Key\KeyStatus;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Port\SigningKeyRepositoryInterface;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * The keys of the tenant with their state and every date of their life (architecture §3.3): the ones the
 * JWK Set publishes, and the retired ones on request.
 */
#[AsCommand(
    name: 'heidi:keys:list',
    description: 'List the signing keys of the tenant with their status and dates: the published ones, or every key with --all.',
)]
final readonly class KeysListCommand
{
    public function __construct(
        private TenantProvider $tenants,
        private SigningKeyRepositoryInterface $keys,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Option(description: 'Include the retired keys, out of the JWK Set for good.')]
        bool $all = false,
    ): int {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }

        $keys = $all ? $this->keys->findAll($tenant) : $this->keys->findPublished($tenant);
        if ($keys === []) {
            $io->warning(sprintf('The tenant "%s" has no %s key: nothing can be signed. Run "heidi:keys:rotate".', $tenant->slug, $all ? 'signing' : 'published'));

            return Command::SUCCESS;
        }

        foreach ($keys as $key) {
            $io->definitionList(...self::describe($key));
        }

        return Command::SUCCESS;
    }

    /**
     * The dates a key has, by the transitions it went through; a staged key says when it activates.
     *
     * @return list<array<string, string>>
     */
    private static function describe(SigningKey $key): array
    {
        $rows = [
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
                'Created at' => self::date($key->createdAt),
            ],
        ];
        if ($key->status === KeyStatus::Staged) {
            $rows[] = [
                'Activates at' => self::date($key->activationDueAt),
            ];

            return $rows;
        }
        $rows[] = [
            'Activated at' => self::date($key->activatedAt),
        ];
        if ($key->status === KeyStatus::Active) {
            return $rows;
        }
        $rows[] = [
            'Retiring since' => self::date($key->retiringAt),
        ];
        $rows[] = [
            'Retirement due at' => self::date($key->retirementDueAt),
        ];
        if ($key->status === KeyStatus::Retired) {
            $rows[] = [
                'Retired at' => self::date($key->retiredAt),
            ];
        }

        return $rows;
    }

    private static function date(?DateTimeImmutable $date): string
    {
        return $date?->format(DateTimeInterface::RFC3339) ?? '?';
    }
}
