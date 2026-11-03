<?php

declare(strict_types=1);

namespace App\Doctrine\Repository;

use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use App\Doctrine\EntityManagers;
use App\Doctrine\Listener\ClientResolver;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\DeadRecordsInterface;
use Beffroi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRecord;
use Beffroi\Oidc\Port\PushedAuthorizationRecordRepositoryInterface;
use function is_string;
use function sprintf;

/**
 * The records of pushed authorization requests, in beffroi_pushed_authorization_request (RFC 9126 §2.2).
 * A record of a client no longer registered is not found, as a code of one is not.
 *
 * @extends DoctrineRepository<PushedAuthorizationRecord>
 */
final readonly class DoctrinePushedAuthorizationRecordRepository extends DoctrineRepository implements
    DeadRecordsInterface,
    PushedAuthorizationRecordRepositoryInterface
{
    public function __construct(
        EntityManagers $managers,
        private BoundedDelete $sweep,
    ) {
        parent::__construct($managers, PushedAuthorizationRecord::class);
    }

    /**
     * A record stays until it expires, so that a second presentation of the reference is told from one
     * nobody ever issued (RFC 9126 §4); past that it grants nothing whether the store holds it or not, and
     * nothing else ever reads it. The interaction a push started names it by its hash and not by a key, so
     * no row waits on this one.
     *
     * This is the table the question was asked of (issue #177): it is the first the provider writes to with
     * no user involved at all, a client authenticating, posting, and leaving behind a row that is worth
     * nothing sixty seconds later.
     */
    public function forgetWhatIsDead(Tenant $tenant, DateTimeImmutable $now, int $limit): int
    {
        $expiry = $this->sweep->column(PushedAuthorizationRecord::class, 'expiresAt');

        return $this->sweep->from(
            PushedAuthorizationRecord::class,
            $tenant,
            sprintf('%s <= :now', $expiry),
            $expiry,
            [
                'now' => $now,
            ],
            [
                'now' => Types::DATETIME_IMMUTABLE,
            ],
            $limit,
        );
    }

    public function findByRequestUriHash(string $requestUriHash): ?PushedAuthorizationRecord
    {
        $record = $this->repository()->findOneBy([
            'requestUriHash' => $requestUriHash,
        ]);

        return $record !== null && ClientResolver::isResolved($record) ? $record : null;
    }

    /**
     * One UPDATE ... WHERE used_at IS NULL through the connection, not the unit of work: the count of
     * affected rows says who claimed the row. The loser reads the date back so that its copy says what
     * the winner wrote.
     */
    public function consume(PushedAuthorizationRecord $record, DateTimeImmutable $now): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(PushedAuthorizationRecord::class);
        $claimed =
            $manager->getConnection()->executeStatement(
                sprintf(
                    'UPDATE %s SET %s = :now WHERE %s = :requestUriHash AND %s IS NULL',
                    $metadata->getTableName(),
                    $metadata->getColumnName('usedAt'),
                    $metadata->getColumnName('requestUriHash'),
                    $metadata->getColumnName('usedAt'),
                ),
                [
                    'now' => $now,
                    'requestUriHash' => $record->requestUriHash,
                ],
                [
                    'now' => Types::DATETIME_IMMUTABLE,
                    'requestUriHash' => ParameterType::STRING,
                ],
            ) === 1;
        if ($claimed) {
            $record->consume($now);

            return true;
        }
        $usedAt = $manager->getConnection()->fetchOne(
            sprintf(
                'SELECT %s FROM %s WHERE %s = :requestUriHash',
                $metadata->getColumnName('usedAt'),
                $metadata->getTableName(),
                $metadata->getColumnName('requestUriHash'),
            ),
            [
                'requestUriHash' => $record->requestUriHash,
            ],
            [
                'requestUriHash' => ParameterType::STRING,
            ],
        );
        if (is_string($usedAt)) {
            $record->recordConsumption(new DateTimeImmutable($usedAt));
        }

        return false;
    }

    public function save(PushedAuthorizationRecord $record): void
    {
        $this->store($record);
    }
}
