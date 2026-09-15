<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use Doctrine\Persistence\ManagerRegistry;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;

/**
 * Authorization codes in heidi_authorization_code (architecture §4.4), keyed by their hash. A code of a
 * client that is no longer registered is not found: an unknown code, which is what the grant refuses.
 *
 * @extends DoctrineRepository<AuthorizationCode>
 */
final readonly class DoctrineAuthorizationCodeRepository extends DoctrineRepository implements AuthorizationCodeRepositoryInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, AuthorizationCode::class);
    }

    public function findByCodeHash(string $codeHash): ?AuthorizationCode
    {
        $code = $this->repository()
            ->findOneBy([
                'codeHash' => $codeHash,
            ]);

        return $code !== null && ClientResolver::isResolved($code) ? $code : null;
    }

    public function save(AuthorizationCode $code): void
    {
        $this->store($code);
    }
}
