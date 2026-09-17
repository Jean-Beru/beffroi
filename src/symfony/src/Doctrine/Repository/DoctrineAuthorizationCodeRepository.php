<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Doctrine\Persistence\ManagerRegistry;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use function is_string;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Authorization codes in heidi_authorization_code (architecture §4.4), keyed by their hash. A code of a
 * client that is no longer registered is not found: an unknown code, which is what the grant refuses.
 *
 * consume() is one conditional statement, not a read followed by a write: the database decides which of
 * the requests presenting the same code at once is the first, and the others are replays.
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

    public function findByGrantId(Uuid $grantId): ?AuthorizationCode
    {
        $code = $this->repository()
            ->findOneBy([
                'grantId' => $grantId,
            ]);

        return $code !== null && ClientResolver::isResolved($code) ? $code : null;
    }

    /**
     * One UPDATE ... WHERE used_at IS NULL: the row is claimed by whoever the database lets write it,
     * and the count of affected rows says who that was. The statement goes through the connection
     * rather than the unit of work, which would read the entity it already holds. The loser reads the
     * date back and records it, so that its copy says what the winner wrote and so that saving the
     * revocation of the grant does not write a null over it; the record cannot be rehydrated, its
     * properties being readonly.
     */
    public function consume(AuthorizationCode $code, DateTimeImmutable $now): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(AuthorizationCode::class);
        $claimed = $manager->getConnection()
            ->executeStatement(
                sprintf(
                    'UPDATE %s SET %s = :now WHERE %s = :codeHash AND %s IS NULL',
                    $metadata->getTableName(),
                    $metadata->getColumnName('usedAt'),
                    $metadata->getColumnName('codeHash'),
                    $metadata->getColumnName('usedAt'),
                ),
                [
                    'now' => $now,
                    'codeHash' => $code->codeHash,
                ],
                [
                    'now' => Types::DATETIME_IMMUTABLE,
                    'codeHash' => ParameterType::STRING,
                ],
            ) === 1;
        if ($claimed) {
            $code->consume($now);

            return true;
        }
        $usedAt = $manager->getConnection()
            ->fetchOne(
                sprintf(
                    'SELECT %s FROM %s WHERE %s = :codeHash',
                    $metadata->getColumnName('usedAt'),
                    $metadata->getTableName(),
                    $metadata->getColumnName('codeHash'),
                ),
                [
                    'codeHash' => $code->codeHash,
                ],
                [
                    'codeHash' => ParameterType::STRING,
                ],
            );
        if (is_string($usedAt)) {
            $code->recordConsumption(new DateTimeImmutable($usedAt));
        }

        return false;
    }

    public function save(AuthorizationCode $code): void
    {
        $this->store($code);
    }
}
