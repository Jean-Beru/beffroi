<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use function array_is_list;
use function bin2hex;
use function chr;
use function count;
use function file_put_contents;
use function gzclose;
use function gzopen;
use function gzwrite;
use function is_array;
use function is_float;
use function is_int;
use function gzencode;
use function is_string;
use function ltrim;
use function ord;
use function pack;
use function random_bytes;
use function sprintf;
use function str_pad;
use function str_repeat;
use function str_split;
use function strlen;
use function strrpos;
use function substr_replace;
use const STR_PAD_LEFT;
use function substr;
use Beffroi\Core\Exception\InvalidArgumentException;

final class MaxMindDatabase
{
    public const string KNOWN_ADDRESS = '203.0.113.10';

    public const string UNKNOWN_ADDRESS = '10.0.0.1';

    public const string CITY_EDITION = 'GeoLite2-City';

    public const string ASN_EDITION = 'GeoLite2-ASN';

    private const string METADATA_START_MARKER = "\xAB\xCD\xEF" . 'MaxMind.com';

    private const int TAR_BLOCK = 512;

    private const int PADDING_CHUNK = 1_048_576;

    private const int NODE_COUNT = 1;

    private const int RECORD_SIZE = 24;

    /**
     * @param array<string, mixed> $record
     */
    public static function of(string $databaseType, array $record, int $buildEpoch = 1_767_225_600): string
    {
        $tree = self::node(self::NODE_COUNT) . self::node(self::NODE_COUNT + 16);
        $data = self::encode($record);
        $metadata = self::encode([
            'binary_format_major_version' => 2,
            'binary_format_minor_version' => 0,
            'build_epoch' => $buildEpoch,
            'database_type' => $databaseType,
            'description' => [
                'en' => 'A database of the tests of Beffroi.',
            ],
            'ip_version' => 4,
            'languages' => ['en'],
            'node_count' => self::NODE_COUNT,
            'record_size' => self::RECORD_SIZE,
        ]);

        return $tree . str_repeat("\0", 16) . $data . self::METADATA_START_MARKER . $metadata;
    }

    public static function city(): string
    {
        return self::of(self::CITY_EDITION, [
            'country' => [
                'iso_code' => 'GB',
                'names' => [
                    'en' => 'United Kingdom',
                ],
            ],
            'subdivisions' => [
                [
                    'iso_code' => 'ENG',
                    'names' => [
                        'en' => 'England',
                    ],
                ],
                [
                    'iso_code' => 'OXF',
                    'names' => [
                        'en' => 'Oxfordshire',
                    ],
                ],
            ],
            'city' => [
                'names' => [
                    'en' => 'Oxford',
                ],
            ],
            'location' => [
                'latitude' => 51.752,
                'longitude' => -1.2577,
                'accuracy_radius' => 20,
            ],
        ]);
    }

    public static function asn(): string
    {
        return self::of(self::ASN_EDITION, [
            'autonomous_system_number' => 64_268,
            'autonomous_system_organization' => 'Example Networks',
        ]);
    }

    public static function archived(
        string $database,
        string $directory = 'GeoLite2-City_20260101',
        string $name = self::CITY_EDITION . '.mmdb',
        string $licence = 'The terms of the licence of somebody else.',
        string $copyright = 'Database and Contents Copyright of somebody else.',
    ): string {
        $gzipped = gzencode(self::tarred($database, $directory, $name, $licence, $copyright));
        if ($gzipped === false) {
            throw new InvalidArgumentException('The archive of this fixture cannot be gzipped.');
        }

        return $gzipped;
    }

    public static function tarred(
        string $database,
        string $directory = 'GeoLite2-City_20260101',
        string $name = self::CITY_EDITION . '.mmdb',
        string $licence = 'The terms of the licence of somebody else.',
        string $copyright = 'Database and Contents Copyright of somebody else.',
    ): string {
        return (
            self::member($directory . '/COPYRIGHT.txt', $copyright)
            . self::member($directory . '/' . $name, $database)
            . self::member($directory . '/LICENSE.txt', $licence)
            . str_repeat("\0", 1024)
        );
    }

    public static function archivedTo(string $path, string $database, int $padding): void
    {
        $metadata = strrpos($database, self::METADATA_START_MARKER);
        $archive = gzopen($path, 'wb0');
        if ($metadata === false || $archive === false) {
            throw new InvalidArgumentException(sprintf('The archive of this fixture cannot be written to "%s".', $path));
        }
        $length = strlen($database) + $padding;
        gzwrite($archive, self::header('GeoLite2-City_20260101/' . self::CITY_EDITION . '.mmdb', $length));
        gzwrite($archive, substr($database, 0, $metadata));
        $zeros = str_repeat("\0", self::PADDING_CHUNK);
        for ($left = $padding; $left > 0; $left -= self::PADDING_CHUNK) {
            gzwrite($archive, $left < self::PADDING_CHUNK ? substr($zeros, 0, $left) : $zeros);
        }
        gzwrite($archive, substr($database, $metadata));
        gzwrite($archive, str_repeat("\0", self::paddingOf($length) + 1024));
        gzclose($archive);
    }

    public static function inFile(string $database, string $directory): string
    {
        $path = $directory . '/' . bin2hex(random_bytes(8)) . '.mmdb';
        if (file_put_contents($path, $database) === false) {
            throw new InvalidArgumentException(sprintf('The database of this fixture cannot be written to "%s".', $path));
        }

        return $path;
    }

    private static function member(string $name, string $content): string
    {
        return self::header($name, strlen($content)) . $content . str_repeat("\0", self::paddingOf(strlen($content)));
    }

    private static function header(string $name, int $length): string
    {
        $header =
            str_pad($name, 100, "\0")
            . str_pad('0000644', 8, "\0")
            . str_pad('0000000', 8, "\0")
            . str_pad('0000000', 8, "\0")
            . str_pad(sprintf('%011o', $length), 12, "\0")
            . str_pad(sprintf('%011o', 0), 12, "\0")
            . str_repeat(' ', 8)
            . '0'
            . str_repeat("\0", 100)
            . str_pad('ustar', 6, "\0")
            . '00'
            . str_repeat("\0", 247);
        $checksum = 0;
        foreach (str_split($header) as $byte) {
            $checksum += ord($byte);
        }

        return substr_replace($header, str_pad(sprintf('%06o', $checksum), 7, "\0") . ' ', 148, 8);
    }

    private static function paddingOf(int $length): int
    {
        return (self::TAR_BLOCK - ($length % self::TAR_BLOCK)) % self::TAR_BLOCK;
    }

    private static function node(int $value): string
    {
        return substr(pack('N', $value), 4 - (self::RECORD_SIZE / 8));
    }

    private static function encode(mixed $value): string
    {
        if (is_string($value)) {
            return self::control(2, strlen($value)) . $value;
        }
        if (is_float($value)) {
            return self::control(3, 8) . pack('E', $value);
        }
        if (is_int($value)) {
            $bytes = ltrim(pack('N', $value), "\0");

            return self::control(6, strlen($bytes)) . $bytes;
        }
        if (! is_array($value)) {
            throw new InvalidArgumentException('A record of this fixture holds maps, arrays, strings, doubles and integers.');
        }
        if (array_is_list($value)) {
            $items = '';
            foreach ($value as $item) {
                $items .= self::encode($item);
            }

            return self::control(11, count($value)) . $items;
        }
        $entries = '';
        foreach ($value as $key => $entry) {
            $entries .= self::encode((string) $key) . self::encode($entry);
        }

        return self::control(7, count($value)) . $entries;
    }

    private static function control(int $type, int $size): string
    {
        $extended = $type > 7 ? self::byte($type - 7) : '';
        $head = $type > 7 ? 0 : $type << 5;
        if ($size < 29) {
            return self::byte($head | $size) . $extended;
        }
        if ($size < 285) {
            return self::byte($head | 29) . $extended . self::byte($size - 29);
        }

        return self::byte($head | 30) . $extended . str_pad(substr(pack('N', $size - 285), 2), 2, "\0", STR_PAD_LEFT);
    }

    private static function byte(int $value): string
    {
        if ($value < 0 || $value > 255) {
            throw new InvalidArgumentException('A value of this fixture is too long for the format.');
        }

        return chr($value);
    }
}
