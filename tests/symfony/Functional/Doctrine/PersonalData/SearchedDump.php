<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine\PersonalData;

use Doctrine\DBAL\Connection;
use function array_keys;
use function file_exists;
use function file_get_contents;
use function is_resource;
use function is_scalar;
use function json_encode;
use const JSON_UNESCAPED_UNICODE;
use function sprintf;
use function str_contains;
use function stream_get_contents;
use function strlen;
use function strpos;
use function trim;

/**
 * The bytes of a database, searched for values that must not be in them.
 *
 * It searches the file and not the rows, which is the whole point: a value leaks through an index, a page
 * a row was deleted from, the write-ahead log or the journal exactly as it leaks through a column, and a
 * backup carries all of those. The rows are then read only to say where a hit came from, because a finding
 * that names the value, the table and the column is a finding somebody can fix, and one that says "a
 * fixture value was found" costs an hour to turn into a fix.
 *
 * A value found in no column is reported all the same, with its offset and the file it is in: it is in a
 * page no row claims any more, which is a leak and not a false alarm.
 */
final readonly class SearchedDump
{
    /**
     * @param array<string, string> $files the bytes of each file, by the name a finding calls it
     */
    private function __construct(
        private array $files,
    ) {
    }

    /**
     * The database file and whatever SQLite keeps beside it.
     *
     * The write-ahead log and the rollback journal hold pages that have been written and not yet folded
     * back into the file, so a search that skipped them would search a database the engine does not
     * consider complete.
     */
    public static function of(string $path): self
    {
        $files = [];
        foreach (['' => 'the database', '-wal' => 'the write-ahead log', '-journal' => 'the rollback journal'] as $suffix => $name) {
            if (file_exists($path . $suffix)) {
                $bytes = file_get_contents($path . $suffix);
                if ($bytes !== false && $bytes !== '') {
                    $files[$name] = $bytes;
                }
            }
        }

        return new self($files);
    }

    /**
     * Every way a value could be written, searched in every file.
     *
     * @param list<string> $values
     *
     * @return list<string> one finding per value found, empty when the dump gives nothing away
     */
    public function findings(Connection $connection, array $values): array
    {
        $findings = [];
        foreach ($values as $value) {
            foreach (self::encodingsOf($value) as $encoding => $needle) {
                foreach ($this->files as $file => $bytes) {
                    $offset = strpos($bytes, $needle);
                    if ($offset === false) {
                        continue;
                    }
                    $findings[] = sprintf(
                        '"%s" appears in the clear, %s, at offset %d of %s, in %s.',
                        $value,
                        $encoding,
                        $offset,
                        $file,
                        self::where($connection, $needle),
                    );
                }
            }
        }

        return $findings;
    }

    /**
     * The encodings a value could have been written in, by the name a finding calls each.
     *
     * The bytes of the value, which is what a column holds; and its JSON escaping, which is what a column
     * holding a document holds, where a slash becomes an escaped slash and a quote an escaped quote. A
     * search for the bytes alone passes on a column it should have failed.
     *
     * @return array<string, string>
     */
    private static function encodingsOf(string $value): array
    {
        $encodings = ['as its own bytes' => $value];

        $json = json_encode($value, JSON_UNESCAPED_UNICODE);
        if ($json !== false) {
            $escaped = trim($json, '"');
            if ($escaped !== $value) {
                $encodings['escaped as JSON'] = $escaped;
            }
        }

        return $encodings;
    }

    /**
     * The column a value sits in, read from the rows rather than from the page it was found in.
     *
     * Every column of every table is walked and not only the ones the provider maps: a value that reached a
     * table of the application, of the bus or of the migrations is as much of a leak. {@see RawRows} is
     * deliberately not reused, because it refuses what it cannot read as text, which is what makes it right
     * for a sealed column and wrong for a walk that meets counters and dates.
     */
    private static function where(Connection $connection, string $needle): string
    {
        $platform = $connection->getDatabasePlatform();
        foreach ($connection->createSchemaManager()->introspectTableNames() as $name) {
            // The name as the platform quotes it to query it, and as a person reads it to name the finding.
            $table = $name->getUnqualifiedName()->getValue();
            foreach ($connection->fetchAllAssociative(sprintf('SELECT * FROM %s', $name->toSQL($platform))) as $row) {
                foreach ($row as $column => $value) {
                    if (str_contains(self::text($value), $needle)) {
                        return sprintf('%s.%s', $table, $column);
                    }
                }
            }
        }

        return 'no column of any table, so in a page no row claims any more';
    }

    private static function text(mixed $value): string
    {
        return match (true) {
            $value === null => '',
            is_resource($value) => (string) stream_get_contents($value),
            is_scalar($value) => (string) $value,
            default => '',
        };
    }

    /**
     * How much was searched, for a test that wants to say it searched something.
     */
    public function bytes(): int
    {
        $bytes = 0;
        foreach ($this->files as $contents) {
            $bytes += strlen($contents);
        }

        return $bytes;
    }

    /**
     * The files a finding can name, for a test that wants to say which were there.
     *
     * @return list<string>
     */
    public function searched(): array
    {
        return array_keys($this->files);
    }
}
