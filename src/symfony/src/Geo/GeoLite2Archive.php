<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Geo;

use function gzdecode;
use function intdiv;
use function octdec;
use function rtrim;
use function str_contains;
use function str_ends_with;
use function str_starts_with;
use function strlen;
use function substr;
use function trim;
use Beffroi\Core\Exception\InvalidArgumentException;

/**
 * The database inside what MaxMind serves (issue #473): a gzipped tar of one directory holding the
 * ".mmdb" file, a licence and a copyright notice. The database is taken out of it and nothing else is,
 * which is the whole of what the refresh command needs of an archive.
 *
 * It reads the two headers of the tar format it needs, the name of a member and its length, and it writes
 * nothing to disk: an archive is a string in a worker's memory, and a directory of extracted files would
 * be a second place a database could be read from.
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
     * One header of the tar format, and the size of the blocks a member is padded to.
     */
    private const int TAR_BLOCK = 512;

    /**
     * @throws InvalidArgumentException when the archive is not one, or holds no database
     */
    public static function database(string $archive): string
    {
        if (! str_starts_with($archive, self::GZIP_MAGIC)) {
            return self::checked($archive);
        }
        $tar = @gzdecode($archive);
        if ($tar === false) {
            throw new InvalidArgumentException('the archive is gzipped and cannot be unpacked');
        }

        return self::checked(self::member($tar));
    }

    /**
     * The one ".mmdb" member of the tar, by walking its headers: the name of a member and its length are
     * the two fields this needs, and a member that is not the database is stepped over.
     *
     * @throws InvalidArgumentException when no member of the archive is a database
     */
    private static function member(string $tar): string
    {
        $offset = 0;
        while (($offset + self::TAR_BLOCK) <= strlen($tar)) {
            $header = substr($tar, $offset, self::TAR_BLOCK);
            if (trim($header, "\0") === '') {
                // The two empty blocks that end an archive.
                break;
            }
            $name = rtrim(substr($header, 0, 100), "\0");
            $length = (int) octdec(trim(substr($header, 124, 12), "\0 "));
            $offset += self::TAR_BLOCK;
            if (str_ends_with($name, '.mmdb')) {
                return substr($tar, $offset, $length);
            }
            $offset += intdiv($length + self::TAR_BLOCK - 1, self::TAR_BLOCK) * self::TAR_BLOCK;
        }

        throw new InvalidArgumentException('no member of the archive is a ".mmdb" database');
    }

    /**
     * @throws InvalidArgumentException when what was taken out is not a MaxMind DB file
     */
    private static function checked(string $database): string
    {
        if (! str_contains($database, self::MAXMIND_DB_MARKER)) {
            throw new InvalidArgumentException('what it holds is not a MaxMind DB file');
        }

        return $database;
    }
}
