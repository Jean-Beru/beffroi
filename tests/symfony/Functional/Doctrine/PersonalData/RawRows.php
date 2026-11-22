<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine\PersonalData;

use Doctrine\DBAL\Connection;
use function get_debug_type;
use function implode;
use function is_resource;
use function is_string;
use LogicException;
use function sprintf;
use function stream_get_contents;

final readonly class RawRows
{
    /**
     * @param list<string> $columns
     *
     * @return list<array<string, string|null>> in no order
     *
     * @throws LogicException if a column holds neither text nor binary
     */
    public static function of(Connection $connection, string $table, array $columns): array
    {
        $rows = [];
        foreach ($connection->fetchAllAssociative(sprintf('SELECT %s FROM %s', implode(', ', $columns), $table)) as $row) {
            $read = [];
            foreach ($row as $column => $value) {
                $read[$column] = match (true) {
                    $value === null => null,
                    is_string($value) => $value,
                    is_resource($value) => (string) stream_get_contents($value),
                    default => throw new LogicException(sprintf(
                        '%s.%s came back as %s: this reads the text and the binary of a sealed table, nothing that has to be rendered.',
                        $table,
                        $column,
                        get_debug_type($value),
                    )),
                };
            }
            $rows[] = $read;
        }

        return $rows;
    }
}
