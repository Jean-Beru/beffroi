<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\PersonalData\BlindIndexedColumns;
use Beffroi\Bundle\Doctrine\PersonalData\TenantBlindIndexes;
use Beffroi\Core\Domain\Identity\LinkedIdentity;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\LinkedIdentityRepositoryInterface;

/**
 * The identities of a user at an upstream provider, in beffroi_linked_identity (architecture §3.1); a lookup is
 * scoped by the tenant and exact, as the unique constraint of the table is.
 *
 * Both columns of the pair are sealed, so neither matches: the format seals every value under a random
 * initialisation vector, and two writes of one subject give two ciphertexts. What the lookup matches is the
 * two blind indexes, in the sibling columns the write filled in the same statement, and those are the
 * columns the unique constraint is held on (decision 0011).
 *
 * @extends DoctrineRepository<LinkedIdentity>
 */
final readonly class DoctrineLinkedIdentityRepository extends DoctrineRepository implements LinkedIdentityRepositoryInterface
{
    public function __construct(
        EntityManagers $managers,
        private TenantBlindIndexes $indexes,
    ) {
        parent::__construct($managers, LinkedIdentity::class);
    }

    /**
     * The projections the tags are derived under are the ones the write used, there being one declaration
     * for both sides.
     */
    public function find(Tenant $tenant, string $provider, string $subject): ?LinkedIdentity
    {
        $providerColumn = BlindIndexedColumns::of(LinkedIdentity::class, 'provider');
        $subjectColumn = BlindIndexedColumns::of(LinkedIdentity::class, 'subject');

        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            $providerColumn->tag => $this->indexes->of($providerColumn)->of($provider),
            $subjectColumn->tag => $this->indexes->of($subjectColumn)->of($subject),
        ]);
    }

    public function save(LinkedIdentity $identity): void
    {
        $this->store($identity);
    }
}
