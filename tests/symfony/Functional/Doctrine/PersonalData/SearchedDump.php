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

final readonly class SearchedDump
{
    /**
     * @param array<string, string> $files the bytes of each file, by name
     */
    private function __construct(
        private array $files,
    ) {
    }

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
     * @param list<string> $values
     *
     * @return list<string> one finding per value found
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
     * The bytes and their JSON escaping: a search for the bytes alone misses a value inside a JSON document.
     *
     * @return array<string, string> each encoding, by name
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

    private static function where(Connection $connection, string $needle): string
    {
        $platform = $connection->getDatabasePlatform();
        foreach ($connection->createSchemaManager()->introspectTableNames() as $name) {
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

    public function bytes(): int
    {
        $bytes = 0;
        foreach ($this->files as $contents) {
            $bytes += strlen($contents);
        }

        return $bytes;
    }

    /**
     * @return list<string>
     */
    public function searched(): array
    {
        return array_keys($this->files);
    }
}
