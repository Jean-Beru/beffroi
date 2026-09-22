<?php

declare(strict_types=1);

namespace Heidi\Bundle\Command;

use function count;
use DateTimeImmutable;
use DateTimeInterface;
use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Core\Domain\Key\KeyStatus;
use Heidi\Core\Domain\Key\TenantKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\ExceptionTrail;
use Heidi\Core\Port\KeySealerInterface;
use Heidi\Core\Port\TenantKeyRepositoryInterface;
use function implode;
use function sprintf;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Attribute\Option;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Style\SymfonyStyle;
use Throwable;

/**
 * The keys of the tenant with what they are published for, their state and every date of their life
 * (architecture §3.3): the ones the JWK Set publishes, and the retired ones on request. On request too,
 * whether the KMS still opens the keys in use or about to be: a KMS that lost its master key leaves
 * envelopes nothing can open, which the first signature, or the first JWE, would be the one to find out.
 */
#[AsCommand(
    name: 'heidi:keys:list',
    description: 'List the keys of the tenant with their use, status and dates: the published ones, or every key with --all; --check opens the keys in use, or about to be, with the KMS and fails on one it cannot open.',
)]
final readonly class KeysListCommand
{
    public function __construct(
        private TenantProvider $tenants,
        private TenantKeyRepositoryInterface $keys,
        private KeySealerInterface $sealer,
    ) {
    }

    public function __invoke(
        SymfonyStyle $io,
        #[Option(description: 'Include the retired keys, out of the JWK Set for good.')]
        bool $all = false,
        #[Option(description: 'Open the active and the staged keys with the KMS and say whether each one opens; a retiring key is opened only to read what was encrypted to it. Fails when one does not open.')]
        bool $check = false,
    ): int {
        try {
            $tenant = $this->tenants->provide();
        } catch (TenantNotSynchronizedException $exception) {
            $io->error([$exception->getMessage(), 'Run "heidi:tenant:synchronize" first.']);

            return Command::FAILURE;
        }

        $keys = $all ? $this->keys->findAll($tenant) : $this->keys->findPublished($tenant);
        if ($keys === []) {
            $io->warning(sprintf('The tenant "%s" has no %skey: nothing can be signed. Run "heidi:keys:rotate".', $tenant->slug, $all ? '' : 'published '));

            return Command::SUCCESS;
        }

        $dead = [];
        foreach ($keys as $key) {
            $rows = self::describe($key);
            if ($check && ($key->status === KeyStatus::Staged || $key->status === KeyStatus::Active)) {
                $failure = $this->failureToOpen($tenant, $key);
                $rows[] = [
                    'Opens with the KMS' => $failure === null ? 'yes' : 'no: ' . $failure,
                ];
                if ($failure !== null) {
                    $dead[] = $key->kid;
                }
            }
            $io->definitionList(...$rows);
        }
        if ($dead !== []) {
            $io->error([
                sprintf('The KMS cannot open the key%s %s of "%s": nothing is done with %s.', count($dead) === 1 ? '' : 's', implode(', ', $dead), $tenant->slug, count($dead) === 1 ? 'it' : 'them'),
                'If the KMS is not reachable, start it and run this command again. If the KMS lost the master key (Vault in dev mode and LocalStack forget everything when they restart), the envelopes sealed under it are dead: "heidi:keys:rotate --now" publishes a key sealed under the key it has now and signs with it at once, the dead key retires with its window, its public half still verifying what it signed. Nothing is deleted.',
            ]);

            return Command::FAILURE;
        }

        return Command::SUCCESS;
    }

    /**
     * Why the KMS does not open the key, or null when it does: the message of the sealer and of what it
     * wraps (the bridge names the KMS it failed to reach or the key it does not know), never the material.
     */
    private function failureToOpen(Tenant $tenant, TenantKey $key): ?string
    {
        try {
            $this->sealer->unseal($tenant, $key->sealedPrivateJwk);
        } catch (Throwable $exception) {
            return ExceptionTrail::of($exception);
        }

        return null;
    }

    /**
     * The dates a key has, by the transitions it went through; a staged key says when it activates.
     *
     * @return list<array<string, string>>
     */
    private static function describe(TenantKey $key): array
    {
        $rows = [
            [
                'Key identifier' => $key->kid,
            ],
            [
                'Algorithm' => $key->algorithm->name(),
            ],
            [
                'Use' => $key->algorithm->keyUse()
                    ->value,
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
