<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Bundle\Doctrine\Listener\ClientResolver;
use Beffroi\Core\Domain\Record\WhatATokenStillNeeds;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\DeadRecordsInterface;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Domain\Device\DeviceAuthorizationRecord;
use Beffroi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Beffroi\Oidc\Port\DeviceAuthorizationRecordRepositoryInterface;
use Beffroi\Oidc\Port\RecordedGrantsInterface;
use SortDirection;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;
use function array_filter;
use function array_values;
use function is_string;
use function sprintf;

/**
 * The records of device authorization requests, in beffroi_device_authorization_request (RFC 8628 §3.2). A
 * record of a client no longer registered is not found, as a code of one is not.
 *
 * @extends DoctrineRepository<DeviceAuthorizationRecord>
 */
final readonly class DoctrineDeviceAuthorizationRecordRepository extends DoctrineRepository implements
    CanRevokeGrantsByConsentInterface,
    DeadRecordsInterface,
    DeviceAuthorizationRecordRepositoryInterface,
    RecordedGrantsInterface
{
    public function __construct(
        EntityManagers $managers,
        private BoundedDelete $sweep,
        private WhatATokenStillNeeds $stillNeeded,
    ) {
        parent::__construct($managers, DeviceAuthorizationRecord::class);
    }

    /**
     * A record row outlives the ten minutes a user has to read a code off one screen and type it on
     * another: this flow writes no authorization code, so the record is the grant its tokens descend from,
     * and a resource server asks this row whether that grant still stands (architecture §4.6,
     * AccessTokenInspector). It waits what a token still needs, exactly as a code does.
     *
     * Counted from the expiry, the column the mapping indexes.
     */
    public function forgetWhatIsDead(Tenant $tenant, DateTimeImmutable $now, int $limit): int
    {
        $expiry = $this->sweep->column(DeviceAuthorizationRecord::class, 'expiresAt');

        return $this->sweep->from(
            DeviceAuthorizationRecord::class,
            $tenant,
            sprintf('%s <= :dead', $expiry),
            $expiry,
            [
                'dead' => $this->stillNeeded->deadBefore($now),
            ],
            [
                'dead' => Types::DATETIME_IMMUTABLE,
            ],
            $limit,
        );
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

    public function findByGrantId(Uuid $grantId): ?DeviceAuthorizationRecord
    {
        return $this->resolved($this->repository()->findOneBy([
            'grantId' => $grantId,
        ]));
    }

    /**
     * The grants a user left to a client on an appliance of theirs, whatever their state. A request nobody
     * has answered yet names no user, so no consent covers it and the ten minutes it has left run out on
     * their own.
     *
     * @return list<DeviceAuthorizationRecord>
     */
    public function revokeByConsent(Consent $consent, DateTimeImmutable $now): array
    {
        /** @var list<DeviceAuthorizationRecord> $records */
        $records = $this->queryBuilder('r')
            ->join('r.session', 's')
            ->where('s.user = :user')
            ->andWhere('r.clientId = :clientId')
            ->andWhere('r.revokedAt IS NULL')
            ->orderBy('r.issuedAt', SortDirection::Ascending)
            ->addOrderBy('r.deviceCodeHash', SortDirection::Ascending)
            ->setParameter('user', $consent->user->id, UuidType::NAME)
            ->setParameter('clientId', $consent->clientId)
            ->getQuery()
            ->getResult();
        $revoked = array_values(array_filter($records, ClientResolver::isResolved(...)));
        foreach ($revoked as $record) {
            $record->revoke($now);
        }
        $this->storeAll($revoked);

        return $revoked;
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
