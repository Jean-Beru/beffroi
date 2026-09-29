<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Heidi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function is_numeric;
use function sprintf;

/**
 * The initial access tokens of a tenant, in heidi_initial_access_token (RFC 7591 §1.2). The value is
 * never here: a row is found by the digest of what the caller presented, so whoever reads the table
 * holds nothing to present.
 *
 * @extends DoctrineRepository<InitialAccessToken>
 */
final readonly class DoctrineInitialAccessTokenRepository extends DoctrineRepository implements InitialAccessTokenRepositoryInterface
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
