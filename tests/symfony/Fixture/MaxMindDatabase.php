<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Fixture;

use function array_is_list;
use function chr;
use function count;
use function is_array;
use function is_float;
use function is_int;
use function gzencode;
use function is_string;
use function ltrim;
use function ord;
use function pack;
use function sprintf;
use function str_pad;
use function str_repeat;
use function str_split;
use function strlen;
use function substr_replace;
use const STR_PAD_LEFT;
use function substr;
use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * A database of addresses in the MaxMind DB format, written here so that what the bundle reads in a test
 * is a file of the format and not a double of the reader (MaxMind DB File Format v2). Nothing of this
 * provider writes one: the editions are published by MaxMind, and this exists so that reading one is
 * tested at all.
 *
 * **One node, two answers.** The search tree holds the one node every lookup starts at: an address whose
 * first bit is 1, which is 128.0.0.0 and above, is the record; every other address is in no network of the
 * database, which is the other half of what a reader must be tried against. IPv4, because an address of
 * the tests is one.
 */
final class MaxMindDatabase
{
    /**
     * An address every database of this fixture answers for.
     */
    public const string KNOWN_ADDRESS = '203.0.113.10';

    /**
     * An address no network of a database of this fixture covers.
     */
    public const string UNKNOWN_ADDRESS = '10.0.0.1';

    public const string CITY_EDITION = 'GeoLite2-City';

    public const string ASN_EDITION = 'GeoLite2-ASN';

    private const string METADATA_START_MARKER = "\xAB\xCD\xEF" . 'MaxMind.com';

    private const int TAR_BLOCK = 512;

    /**
     * The one node of the tree: on the left the value of "no network of this database", which is the
     * number of nodes, on the right the pointer to the one record, which the format reads as
     * "node count + 16 + the offset in the data section".
     */
    private const int NODE_COUNT = 1;

    private const int RECORD_SIZE = 24;

    /**
     * @param array<string, mixed> $record what the database says of an address it covers
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

    /**
     * The city edition of the tests: what GeoLite2-City says of an address, in the shape the edition
     * documents, which is what the bundle reads the country, the subdivision, the city and the
     * coordinates out of.
     */
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

    /**
     * The ASN edition of the tests: the autonomous system of an address and the organisation that holds
     * it, which are the two fields of a GeoLocation the city edition does not carry.
     */
    public static function asn(): string
    {
        return self::of(self::ASN_EDITION, [
            'autonomous_system_number' => 64_268,
            'autonomous_system_organization' => 'Example Networks',
        ]);
    }

    /**
     * What MaxMind serves: a gzipped tar of one directory holding the licence, the copyright notice and
     * the database, which is the shape the refresh takes a database out of. The name of the member is a
     * parameter so that an archive holding no database at all can be served too.
     */
    public static function archived(
        string $database,
        string $directory = 'GeoLite2-City_20260101',
        string $name = self::CITY_EDITION . '.mmdb',
    ): string {
        $tar =
            self::member($directory . '/COPYRIGHT.txt', 'Database and Contents Copyright of somebody else.')
            . self::member($directory . '/' . $name, $database)
            . str_repeat("\0", 1024);
        $gzipped = gzencode($tar);
        if ($gzipped === false) {
            throw new InvalidArgumentException('The archive of this fixture cannot be gzipped.');
        }

        return $gzipped;
    }

    /**
     * One member of a tar: a header of five hundred and twelve bytes, of which this writes the name, the
     * mode, the length and the checksum, then the content padded to the next block.
     */
    private static function member(string $name, string $content): string
    {
        $header =
            str_pad($name, 100, "\0")
            . str_pad('0000644', 8, "\0")
            . str_pad('0000000', 8, "\0")
            . str_pad('0000000', 8, "\0")
            . str_pad(sprintf('%011o', strlen($content)), 12, "\0")
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
        $header = substr_replace($header, str_pad(sprintf('%06o', $checksum), 7, "\0") . ' ', 148, 8);
        $padding = (self::TAR_BLOCK - (strlen($content) % self::TAR_BLOCK)) % self::TAR_BLOCK;

        return $header . $content . str_repeat("\0", $padding);
    }

    /**
     * One record of the search tree, big-endian over the record size of this database.
     */
    private static function node(int $value): string
    {
        return substr(pack('N', $value), 4 - (self::RECORD_SIZE / 8));
    }

    /**
     * A value in the data format: a map, an array, a string, a double or an unsigned integer, which is
     * everything a GeoLite2 record holds.
     */
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

    /**
     * The control byte of a value, and the bytes its size needs beyond the five bits of that byte. A type
     * above seven is written as zero followed by the type itself, which is what the format calls an
     * extended type.
     */
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

    /**
     * One byte of a value this fixture writes, which is a value a byte holds or a fixture written wrong.
     */
    private static function byte(int $value): string
    {
        if ($value < 0 || $value > 255) {
            throw new InvalidArgumentException('A value of this fixture is too long for the format.');
        }

        return chr($value);
    }
}
