<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Heidi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use function is_string;
use function sprintf;

/**
 * The records of device authorization requests, in heidi_device_authorization_request (RFC 8628 §3.2). A
 * record of a client no longer registered is not found, as a code of one is not.
 *
 * @extends DoctrineRepository<DeviceAuthorizationRecord>
 */
final readonly class DoctrineDeviceAuthorizationRecordRepository extends DoctrineRepository implements DeviceAuthorizationRecordRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, DeviceAuthorizationRecord::class);
    }

    public function findByDeviceCodeHash(string $deviceCodeHash): ?DeviceAuthorizationRecord
    {
        return $this->resolved($this->repository()->findOneBy([
            'deviceCodeHash' => $deviceCodeHash,
        ]));
    }

    public function findByUserCodeHash(string $userCodeHash): ?DeviceAuthorizationRecord
    {
        return $this->resolved($this->repository()->findOneBy([
            'userCodeHash' => $userCodeHash,
        ]));
    }

    /**
     * One UPDATE ... WHERE used_at IS NULL through the connection, not the unit of work: the count of
     * affected rows says who claimed the row. The loser reads the date back so that its copy says what the
     * winner wrote.
     */
    public function consume(DeviceAuthorizationRecord $record, DateTimeImmutable $now): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(DeviceAuthorizationRecord::class);
        $claimed =
            $manager->getConnection()->executeStatement(
                sprintf(
                    'UPDATE %s SET %s = :now WHERE %s = :deviceCodeHash AND %s IS NULL',
                    $metadata->getTableName(),
                    $metadata->getColumnName('usedAt'),
                    $metadata->getColumnName('deviceCodeHash'),
                    $metadata->getColumnName('usedAt'),
                ),
                [
                    'now' => $now,
                    'deviceCodeHash' => $record->deviceCodeHash,
                ],
                [
                    'now' => Types::DATETIME_IMMUTABLE,
                    'deviceCodeHash' => ParameterType::STRING,
                ],
            ) === 1;
        if ($claimed) {
            $record->consume($now);

            return true;
        }
        $usedAt = $manager->getConnection()->fetchOne(
            sprintf(
                'SELECT %s FROM %s WHERE %s = :deviceCodeHash',
                $metadata->getColumnName('usedAt'),
                $metadata->getTableName(),
                $metadata->getColumnName('deviceCodeHash'),
            ),
            [
                'deviceCodeHash' => $record->deviceCodeHash,
            ],
            [
                'deviceCodeHash' => ParameterType::STRING,
            ],
        );
        if (is_string($usedAt)) {
            $record->recordConsumption(new DateTimeImmutable($usedAt));
        }

        return false;
    }

    public function save(DeviceAuthorizationRecord $record): void
    {
        $this->store($record);
    }

    private function resolved(?DeviceAuthorizationRecord $record): ?DeviceAuthorizationRecord
    {
        return $record !== null && ClientResolver::isResolved($record) ? $record : null;
    }
}
