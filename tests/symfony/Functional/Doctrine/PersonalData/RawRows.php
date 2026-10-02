<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Doctrine\PersonalData;

use Doctrine\DBAL\Connection;
use function get_debug_type;
use function implode;
use function is_resource;
use function is_string;
use LogicException;
use function sprintf;
use function stream_get_contents;

/**
 * The columns of a table as the database holds them, with nothing converting a type on the way out, which
 * is the whole point of reading a row this way: a test that sealed a column reads it here to see what an
 * operator of the database, or a dump of it, would see.
 *
 * Two things it does and a caller does not have to. A sealed column is binary, so pdo_pgsql hands it back
 * as a stream and not as a string, which is read to the end here. And a column that holds nothing comes
 * back as a null rather than as an empty string, because a test that searches a column for a plaintext
 * passes for the wrong reason when the column is empty, and the caller is the one that knows whether its
 * column may be.
 *
 * It reads the columns a sealed table is asserted on, which are binary or text, and it refuses anything
 * else rather than printing it: a date or a count read through here would come back as a string that looks
 * like a value and is a rendering.
 */
final readonly class RawRows
{
    /**
     * @param list<string> $columns
     *
     * @return list<array<string, string|null>> one entry per row of the table, in no order
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
