<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use function array_values;
use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Doctrine\Persistence\ManagerRegistry;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\Authorization\AuthorizationCode;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Port\AuthorizationCodeRepositoryInterface;
use Heidi\Oidc\Port\LoggedInClientsInterface;
use function is_string;
use function sprintf;
use Symfony\Component\Uid\Uuid;

/**
 * Authorization codes in heidi_authorization_code (architecture §4.4). A code of a client no longer
 * registered is not found.
 *
 * @extends DoctrineRepository<AuthorizationCode>
 */
final readonly class DoctrineAuthorizationCodeRepository extends DoctrineRepository implements AuthorizationCodeRepositoryInterface, LoggedInClientsInterface
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, AuthorizationCode::class);
    }

    public function findByCodeHash(string $codeHash): ?AuthorizationCode
    {
        $code = $this->repository()->findOneBy([
            'codeHash' => $codeHash,
        ]);

        return $code !== null && ClientResolver::isResolved($code) ? $code : null;
    }

    public function findByGrantId(Uuid $grantId): ?AuthorizationCode
    {
        $code = $this->repository()->findOneBy([
            'grantId' => $grantId,
        ]);

        return $code !== null && ClientResolver::isResolved($code) ? $code : null;
    }

    /**
     * The grants of the session that were exchanged for tokens, each client once, oldest grant first. A
     * code still waiting at the token endpoint gave the client no session (Back-Channel Logout 1.0 §2.6),
     * and a code of a client no longer registered names nobody to tell.
     *
     * @return list<Client>
     */
    public function ofSession(Uuid $session): array
    {
        $codes = $this->repository()->findBy([
            'session' => $session,
        ], [
            'issuedAt' => 'ASC',
            'codeHash' => 'ASC',
        ]);
        $clients = [];
        foreach ($codes as $code) {
            if ($code->isUsed() && ClientResolver::isResolved($code)) {
                $clients[$code->clientId] = $code->client;
            }
        }

        return array_values($clients);
    }

    /**
     * One UPDATE ... WHERE used_at IS NULL through the connection, not the unit of work: the count of
     * affected rows says who claimed the row. The loser reads the date back so that its copy says what
     * the winner wrote.
     */
    public function consume(AuthorizationCode $code, DateTimeImmutable $now): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(AuthorizationCode::class);
        $claimed =
            $manager->getConnection()->executeStatement(
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
        $usedAt = $manager->getConnection()->fetchOne(
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
