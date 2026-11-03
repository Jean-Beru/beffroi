<?php

declare(strict_types=1);

namespace App\Geo;

use function fclose;
use function file_get_contents;
use function fopen;
use function fread;
use function fseek;
use function fstat;
use function fwrite;
use Generator;
use function gzopen;
use function implode;
use function intdiv;
use function iterator_count;
use function iterator_to_array;
use function min;
use function octdec;
use const PHP_INT_MAX;
use function rtrim;
use const SEEK_END;
use function str_contains;
use function str_ends_with;
use function stream_get_contents;
use function strlen;
use function substr;
use function trim;
use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * The database inside what MaxMind serves (issue #473): a gzipped tar of one directory holding the
 * ".mmdb" file, a licence and a copyright notice. The database is taken out of it and nothing else is,
 * which is the whole of what the refresh command needs of an archive.
 *
 * **It reads a file and writes another, by stream** (issue #904): what it holds at a time is a chunk of
 * the tar and never the archive, the tar or the database, the archive of the city edition decompressed
 * whole going past the memory PHP gives a process by default. It reads the two fields
 * of a header of the tar format it needs, the name of a member and its length, and it reads the gzip
 * stream to its end, where its check is (RFC 1952 §2.3.1): a stream whose data or check does not hold
 * is refused whole.
 *
 * A file that is not gzipped is taken as the database itself, which is the deployment that downloaded one
 * by hand and names the file it unpacked.
 */
final readonly class GeoLite2Archive
{
    /**
     * The two bytes that open a gzip stream (RFC 1952 §2.3.1).
     */
    private const string GZIP_MAGIC = "\x1f\x8b";

    /**
     * The marker that opens a MaxMind DB file's metadata section, and what says a file is one at all
     * (MaxMind DB File Format v2 §Database Metadata).
     */
    private const string MAXMIND_DB_MARKER = "\xAB\xCD\xEFMaxMind.com";

    /**
     * The most the metadata section takes at the end of a MaxMind DB file, its marker included (MaxMind DB
     * File Format v2 §Database Metadata), and so how far from the end the marker is looked for.
     */
    private const int MAXMIND_DB_METADATA_MAX = 131_072;

    /**
     * One header of the tar format, and the size of the blocks a member is padded to.
     */
    private const int TAR_BLOCK = 512;

    /**
     * The most of a member read at a time.
     */
    private const int CHUNK = 1_048_576;

    /**
     * The database of the archive at the first path, written to the second.
     *
     * @throws InvalidArgumentException when the archive cannot be read, is not one, or holds no database
     */
    public static function unpack(string $archive, string $database): void
    {
        $from = @gzopen($archive, 'rb');
        if ($from === false) {
            throw new InvalidArgumentException('the file cannot be read');
        }
        $to = @fopen($database, 'w+b');
        try {
            if ($to === false) {
                throw new InvalidArgumentException('the database cannot be written where it is unpacked');
            }
            if (@file_get_contents($archive, length: 2) === self::GZIP_MAGIC) {
                self::member($from, $to);
            } else {
                // Read through the same stream, which hands what is not gzipped over as it stands.
                self::copied($from, $to, PHP_INT_MAX);
            }
            self::checked($to);
        } finally {
            fclose($from);
            if ($to !== false) {
                fclose($to);
            }
        }
    }

    /**
     * The one ".mmdb" member of the tar, by walking its headers: the name of a member and its length are
     * the two fields this needs, and a member that is not the database is read past.
     *
     * @param resource $tar
     * @param resource $database
     *
     * @throws InvalidArgumentException when no member of the archive is a database, or the archive cannot be unpacked
     */
    private static function member($tar, $database): void
    {
        while (strlen($header = self::block($tar)) === self::TAR_BLOCK) {
            if (trim($header, "\0") === '') {
                // The two empty blocks that end an archive.
                break;
            }
            $name = rtrim(substr($header, 0, 100), "\0");
            $length = (int) octdec(trim(substr($header, 124, 12), "\0 "));
            if (str_ends_with($name, '.mmdb')) {
                self::copied($tar, $database, $length);
                // The rest of the stream is read too, because its check is at its end.
                iterator_count(self::chunks($tar, PHP_INT_MAX));

                return;
            }
            iterator_count(self::chunks($tar, intdiv($length + self::TAR_BLOCK - 1, self::TAR_BLOCK) * self::TAR_BLOCK));
        }

        throw new InvalidArgumentException('no member of the archive is a ".mmdb" database');
    }

    /**
     * The next block of the tar, shorter at its end.
     *
     * @param resource $tar
     *
     * @throws InvalidArgumentException when the archive cannot be unpacked
     */
    private static function block($tar): string
    {
        return implode('', iterator_to_array(self::chunks($tar, self::TAR_BLOCK), false));
    }

    /**
     * @param resource $from
     * @param resource $to
     *
     * @throws InvalidArgumentException when the archive cannot be unpacked, or the database cannot be written
     */
    private static function copied($from, $to, int $length): void
    {
        foreach (self::chunks($from, $length) as $chunk) {
            if (@fwrite($to, $chunk) !== strlen($chunk)) {
                throw new InvalidArgumentException('the database cannot be written where it is unpacked');
            }
        }
    }

    /**
     * Up to that many bytes of the stream, fewer at its end, a chunk at a time.
     *
     * @param resource $stream
     *
     * @return Generator<int, string>
     *
     * @throws InvalidArgumentException when the stream cannot be read: a gzip stream whose data or check does not hold
     */
    private static function chunks($stream, int $length): Generator
    {
        while ($length > 0) {
            $chunk = @fread($stream, min($length, self::CHUNK));
            if ($chunk === false) {
                throw new InvalidArgumentException('the archive is gzipped and cannot be unpacked');
            }
            if ($chunk === '') {
                return;
            }
            $length -= strlen($chunk);

            yield $chunk;
        }
    }

    /**
     * What was taken out is a MaxMind DB file when its last bytes say so: the marker of its metadata
     * section, no further from its end than that section may be long.
     *
     * @param resource $database
     *
     * @throws InvalidArgumentException when what was taken out is not a MaxMind DB file
     */
    private static function checked($database): void
    {
        $stat = fstat($database);
        $size = $stat === false ? 0 : $stat['size'];
        $tail = fseek($database, -min($size, self::MAXMIND_DB_METADATA_MAX), SEEK_END) === 0 ? stream_get_contents($database) : false;
        if ($tail === false || ! str_contains($tail, self::MAXMIND_DB_MARKER)) {
            throw new InvalidArgumentException('what it holds is not a MaxMind DB file');
        }
    }
}
