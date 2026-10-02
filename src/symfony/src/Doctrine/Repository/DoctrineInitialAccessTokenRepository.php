<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Port\IssuedInitialAccessTokensInterface;
use function is_numeric;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * The initial access tokens of a tenant, in beffroi_initial_access_token (RFC 7591 §1.2). The value is
 * never here: a row is found by the digest of what the caller presented, so whoever reads the table
 * holds nothing to present.
 *
 * @extends DoctrineRepository<InitialAccessToken>
 */
final readonly class DoctrineInitialAccessTokenRepository extends DoctrineRepository implements
    InitialAccessTokenRepositoryInterface,
    IssuedInitialAccessTokensInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, InitialAccessToken::class);
    }

    public function findByDigest(Tenant $tenant, string $digest): ?InitialAccessToken
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'digest' => $digest,
        ]);
    }

    /**
     * One UPDATE ... WHERE through the connection and not the unit of work, as an authorization code is
     * consumed: the count of affected rows says who claimed the registration, so that a token worth one
     * registers one client and not one per request that arrived together. The loser reads the count back,
     * so that its copy says what the winner wrote.
     */
    public function spend(InitialAccessToken $token, DateTimeImmutable $now): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(InitialAccessToken::class);
        $served = $metadata->getColumnName('registrationsServed');
        $claimed =
            $manager->getConnection()->executeStatement(
                sprintf(
                    'UPDATE %s SET %s = %s + 1 WHERE %s = :digest AND %s < %s AND %s IS NULL AND %s > :now',
                    $metadata->getTableName(),
                    $served,
                    $served,
                    $metadata->getColumnName('digest'),
                    $served,
                    $metadata->getColumnName('registrationsAllowed'),
                    $metadata->getColumnName('revokedAt'),
                    $metadata->getColumnName('expiresAt'),
                ),
                [
                    'digest' => $token->digest,
                    'now' => $now,
                ],
                [
                    'digest' => ParameterType::STRING,
                    'now' => Types::DATETIME_IMMUTABLE,
                ],
            ) === 1;
        $token->recordRegistrationsServed($this->registrationsServed($token, $metadata->getTableName(), $served, $metadata->getColumnName('digest')));

        return $claimed;
    }

    public function find(Tenant $tenant, Uuid $id): ?InitialAccessToken
    {
        return $this->repository()->findOneBy([
            'tenant' => $tenant,
            'id' => $id,
        ]);
    }

    /**
     * The most recently issued first, which is the order whoever issued one looks for it in.
     *
     * @return list<InitialAccessToken>
     */
    public function issuedIn(Tenant $tenant): iterable
    {
        return $this->repository()->findBy([
            'tenant' => $tenant,
        ], [
            'issuedAt' => 'DESC',
        ]);
    }

    public function save(InitialAccessToken $token): void
    {
        $this->store($token);
    }

    private function registrationsServed(InitialAccessToken $token, string $table, string $served, string $digest): int
    {
        $count = $this->manager()
            ->getConnection()
            ->fetchOne(
                sprintf('SELECT %s FROM %s WHERE %s = :digest', $served, $table, $digest),
                [
                    'digest' => $token->digest,
                ],
                [
                    'digest' => ParameterType::STRING,
                ],
            );

        return is_numeric($count) ? (int) $count : $token->registrationsServed;
    }
}
