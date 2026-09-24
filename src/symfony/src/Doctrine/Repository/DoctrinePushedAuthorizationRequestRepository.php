<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine\Repository;

use DateTimeImmutable;
use Doctrine\DBAL\ParameterType;
use Doctrine\DBAL\Types\Types;
use Heidi\Bundle\Doctrine\EntityManagers;
use Heidi\Bundle\Doctrine\Listener\ClientResolver;
use Heidi\Oidc\Domain\PushedAuthorization\PushedAuthorizationRequest;
use Heidi\Oidc\Port\PushedAuthorizationRequestRepositoryInterface;
use function is_string;
use function sprintf;

/**
 * Pushed authorization requests in heidi_pushed_authorization_request (RFC 9126 §2.2). A request of a
 * client no longer registered is not found, as a code of one is not.
 *
 * @extends DoctrineRepository<PushedAuthorizationRequest>
 */
final readonly class DoctrinePushedAuthorizationRequestRepository extends DoctrineRepository implements PushedAuthorizationRequestRepositoryInterface
{
    public function __construct(EntityManagers $managers)
    {
        parent::__construct($managers, PushedAuthorizationRequest::class);
    }

    public function findByRequestUriHash(string $requestUriHash): ?PushedAuthorizationRequest
    {
        $request = $this->repository()->findOneBy([
            'requestUriHash' => $requestUriHash,
        ]);

        return $request !== null && ClientResolver::isResolved($request) ? $request : null;
    }

    /**
     * One UPDATE ... WHERE used_at IS NULL through the connection, not the unit of work: the count of
     * affected rows says who claimed the row. The loser reads the date back so that its copy says what
     * the winner wrote.
     */
    public function consume(PushedAuthorizationRequest $request, DateTimeImmutable $now): bool
    {
        $manager = $this->manager();
        $metadata = $manager->getClassMetadata(PushedAuthorizationRequest::class);
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
                    'requestUriHash' => $request->requestUriHash,
                ],
                [
                    'now' => Types::DATETIME_IMMUTABLE,
                    'requestUriHash' => ParameterType::STRING,
                ],
            ) === 1;
        if ($claimed) {
            $request->consume($now);

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
                'requestUriHash' => $request->requestUriHash,
            ],
            [
                'requestUriHash' => ParameterType::STRING,
            ],
        );
        if (is_string($usedAt)) {
            $request->recordConsumption(new DateTimeImmutable($usedAt));
        }

        return false;
    }

    public function save(PushedAuthorizationRequest $request): void
    {
        $this->store($request);
    }
}
