<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use function array_filter;
use function array_values;
use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\Ciba\BackchannelAuthenticationRecord;
use Heidi\Oidc\Domain\Consent\Consent;
use Heidi\Oidc\Port\BackchannelAuthenticationRecordRepositoryInterface;
use Heidi\Oidc\Port\CanRevokeGrantsByConsentInterface;
use Heidi\Oidc\Port\RecordedGrantsInterface;
use Symfony\Component\Uid\Uuid;
use Symfony\Bridge\Doctrine\Types\UuidType;
use function is_string;
use function sprintf;

/**
 * The records of backchannel authentication requests, in heidi_backchannel_authentication_request (CIBA
 * Core §7). A record of a client no longer registered is not found, as an identifier of one is not.
 *
 * @extends DoctrineRepository<BackchannelAuthenticationRecord>
 */
final readonly class DoctrineBackchannelAuthenticationRecordRepository extends DoctrineRepository implements
    BackchannelAuthenticationRecordRepositoryInterface,
    CanRevokeGrantsByConsentInterface,
    RecordedGrantsInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, BackchannelAuthenticationRecord::class);
    }

    public function findByAuthRequestIdHash(string $authRequestIdHash): ?BackchannelAuthenticationRecord
    {
        $record = $this->repository()->findOneBy([
            'authRequestIdHash' => $authRequestIdHash,
        ]);

        return $record !== null && ClientResolver::isResolved($record) ? $record : null;
    }

    public function awaitingAnAnswerBy(User $user, DateTimeImmutable $now): array
    {
        /** @var list<BackchannelAuthenticationRecord> $records */
        $records = $this->queryBuilder('r')
            ->where('r.user = :user')
            ->andWhere('r.expiresAt > :now')
            ->andWhere('r.approvedAt IS NULL')
            ->andWhere('r.deniedAt IS NULL')
            ->andWhere('r.usedAt IS NULL')
            ->setParameter('user', $user->id, UuidType::NAME)
            ->setParameter('now', $now, Types::DATETIME_IMMUTABLE)
            ->orderBy('r.issuedAt', 'ASC')
            ->getQuery()
            ->getResult();

        return array_values(array_filter($records, ClientResolver::isResolved(...)));
    }

    public function findByGrantId(Uuid $grantId): ?BackchannelAuthenticationRecord
    {
        $record = $this->repository()->findOneBy([
            'grantId' => $grantId,
        ]);

        return $record !== null && ClientResolver::isResolved($record) ? $record : null;
    }

    /**
     * The grants a client asked a user for through a backchannel, whatever their state: the request names
     * its user before anybody answers it, so one still waiting is covered by the consent and is revoked
     * with it.
     *
     * @return list<BackchannelAuthenticationRecord>
     */
    public function revokeByConsent(Consent $consent, DateTimeImmutable $now): array
    {
        /** @var list<BackchannelAuthenticationRecord> $records */
        $records = $this->queryBuilder('r')
            ->where('r.user = :user')
            ->andWhere('r.clientId = :clientId')
            ->andWhere('r.revokedAt IS NULL')
            ->orderBy('r.issuedAt', 'ASC')
            ->addOrderBy('r.authRequestIdHash', 'ASC')
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
    public function consume(BackchannelAuthenticationRecord $record, DateTimeImmutable $now): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(BackchannelAuthenticationRecord::class);
        $claimed =
            $manager->getConnection()->executeStatement(
                sprintf(
                    'UPDATE %s SET %s = :now WHERE %s = :authRequestIdHash AND %s IS NULL',
                    $metadata->getTableName(),
                    $metadata->getColumnName('usedAt'),
                    $metadata->getColumnName('authRequestIdHash'),
                    $metadata->getColumnName('usedAt'),
                ),
                [
                    'now' => $now,
                    'authRequestIdHash' => $record->authRequestIdHash,
                ],
                [
                    'now' => Types::DATETIME_IMMUTABLE,
                    'authRequestIdHash' => ParameterType::STRING,
                ],
            ) === 1;
        if ($claimed) {
            $record->consume($now);

            return true;
        }
        $usedAt = $manager->getConnection()->fetchOne(
            sprintf(
                'SELECT %s FROM %s WHERE %s = :authRequestIdHash',
                $metadata->getColumnName('usedAt'),
                $metadata->getTableName(),
                $metadata->getColumnName('authRequestIdHash'),
            ),
            [
                'authRequestIdHash' => $record->authRequestIdHash,
            ],
            [
                'authRequestIdHash' => ParameterType::STRING,
            ],
        );
        if (is_string($usedAt)) {
            $record->recordConsumption(new DateTimeImmutable($usedAt));
        }

        return false;
    }

    public function save(BackchannelAuthenticationRecord $record): void
    {
        $this->store($record);
    }
}
