<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Doctrine\Repository;

use Beffroi\Bundle\Doctrine\EntityManagers;
use Beffroi\Core\Domain\Tenant\Tenant;
use Doctrine\DBAL\ParameterType;
use function sprintf;
use Symfony\Bridge\Doctrine\Types\UuidType;

/**
 * The delete a store of dead rows makes (issue #177): bounded, held to one tenant, reading no row into
 * memory. Written once because eight stores make it, and a block written a second time is a class.
 *
 * **It goes through the connection and not the unit of work**, as the atomic consumption of a record read
 * once does, and for a reason of its own: hydrating a row to delete it would open every sealed column it
 * carries and ask the KMS for a data key of the tenant (decision 0011), so sweeping a hundred thousand
 * rows would be a hundred thousand openings of what nobody is going to look at. One statement per table,
 * the keys chosen by a subquery, what has waited longest first, and nothing constructed.
 *
 * **The tenant is written here and not in each predicate**: every table of the bundle but `beffroi_tenant`
 * carries it (architecture §5.3), and a store that forgot it would be a store that swept another tenant.
 */
final readonly class BoundedDelete
{
    /**
     * What the tenant is bound as, named so that no predicate of a caller can collide with it.
     */
    private const string TENANT = 'beffroiTenantOfTheSweep';

    public function __construct(
        private EntityManagers $managers,
    ) {
    }

    /**
     * @param class-string $class the entity whose table is swept
     * @param string $where what makes one of its rows dead, written in columns of that table
     * @param string $oldestFirst the column that orders the sweep, so that what has waited longest goes first
     * @param array<string, mixed> $parameters what that predicate names, beside the tenant
     * @param array<string, string|ParameterType> $types the type of each of them
     * @param int $limit how many rows this statement may drop, at most
     *
     * @return int how many it dropped
     */
    public function from(
        string $class,
        Tenant $tenant,
        string $where,
        string $oldestFirst,
        array $parameters,
        array $types,
        int $limit,
    ): int {
        $manager = $this->managers->forClass($class);
        $metadata = $manager->getClassMetadata($class);
        $key = $metadata->getSingleIdentifierColumnName();

        return (int) $manager->getConnection()->executeStatement(
            sprintf(
                'DELETE FROM %1$s WHERE %2$s IN (SELECT %2$s FROM %1$s WHERE %3$s = :%4$s AND (%5$s) ORDER BY %6$s ASC, %2$s ASC LIMIT %7$d)',
                $metadata->getTableName(),
                $key,
                $metadata->getSingleAssociationJoinColumnName('tenant'),
                self::TENANT,
                $where,
                $oldestFirst,
                $limit,
            ),
            [
                ...$parameters,
                self::TENANT => $tenant->id,
            ],
            [
                ...$types,
                self::TENANT => UuidType::NAME,
            ],
        );
    }

    /**
     * The column a field is mapped to, so that a predicate is written in what the mapping says and never
     * in a name copied beside it.
     *
     * @param class-string $class
     */
    public function column(string $class, string $field): string
    {
        return $this->managers->forClass($class)->getClassMetadata($class)->getColumnName($field);
    }

    /**
     * The column a foreign key is written in, which is not a field and is not answered by the same
     * question.
     *
     * @param class-string $class
     */
    public function joinColumn(string $class, string $association): string
    {
        return $this->managers->forClass($class)->getClassMetadata($class)->getSingleAssociationJoinColumnName($association);
    }

    /**
     * @param class-string $class
     */
    public function table(string $class): string
    {
        return $this->managers->forClass($class)->getClassMetadata($class)->getTableName();
    }
}
