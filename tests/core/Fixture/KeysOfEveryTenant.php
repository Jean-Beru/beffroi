<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_any;
use Beffroi\Core\Bridge\JwtLibrary\JwtLibraryKeyPairGenerator;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\SignatureAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use LogicException;

/**
 * An active key for each algorithm it is given, whatever tenant asks: for a test of what the provider announces or
 * accepts, which is not about the keys themselves, under a tenant the test draws anew.
 */
final class KeysOfEveryTenant implements TenantKeyRepositoryInterface
{
    /**
     * @var array<string, GeneratedKeyPair>
     */
    private static array $pairs = [];

    /**
     * @param list<SignatureAlgorithmInterface> $held
     */
    public function __construct(
        private readonly array $held,
    ) {
    }

    public function find(Tenant $tenant, string $kid): ?TenantKey
    {
        return null;
    }

    public function findActive(Tenant $tenant, KeyAlgorithmInterface $algorithm): ?TenantKey
    {
        if (! array_any($this->held, static fn (SignatureAlgorithmInterface $held): bool => $held->name() === $algorithm->name())) {
            return null;
        }

        return new HeldKeys($tenant)->active(
            $algorithm,
            self::$pairs[$algorithm->name()] ??= new JwtLibraryKeyPairGenerator(Algorithms::everyUse())->generate($algorithm),
        );
    }

    public function findInService(Tenant $tenant): array
    {
        return [];
    }

    public function findAll(Tenant $tenant): array
    {
        return [];
    }

    public function save(TenantKey $key): void
    {
        throw new LogicException('These keys are held for every tenant and never stored.');
    }
}
