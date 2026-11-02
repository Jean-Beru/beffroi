<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Geo;

use function bin2hex;
use function chmod;
use Closure;
use function copy;
use function file_get_contents;
use function file_put_contents;
use function in_array;
use function is_dir;
use function is_file;
use function is_readable;
use const LOCK_EX;
use function mkdir;
use function random_bytes;
use function rename;
use function sprintf;
use function trim;
use function unlink;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\RuntimeException;

/**
 * Where the databases of addresses this deployment holds are kept (issue #473), one file per edition under
 * "<storage>/<edition>.mmdb", next to the sealed keys and the FIDO metadata and written the same way,
 * through a sibling file renamed into place so that a lookup never reads half a database.
 *
 * **A directory that holds nothing is the normal state of a new installation**: the editions are published
 * by somebody else under their own licence, so nothing ships them and nothing downloads them until a
 * deployment names its licence key. Every flow is served all the same, with a provenance that says an
 * address and no place.
 *
 * Beside each database is the ETag MaxMind served it with, which is what lets the weekly refresh ask
 * whether anything changed instead of downloading sixty megabytes to write the same bytes again.
 */
final readonly class GeoLite2Databases
{
    /**
     * The country, the subdivision, the city and the coordinates of an address.
     */
    public const string CITY = 'GeoLite2-City';

    /**
     * The network of an address: the number of its autonomous system and the organisation that holds it.
     */
    public const string ASN = 'GeoLite2-ASN';

    /**
     * The editions the enrichment reads, which together carry the seven fields of a GeoLocation. An
     * edition outside this list is refused rather than stored: a file nothing reads is a file nobody
     * notices is the wrong one.
     *
     * @var non-empty-list<string>
     */
    public const array EDITIONS = [self::CITY, self::ASN];

    public function __construct(
        private string $directory,
    ) {
    }

    /**
     * The file of that edition, or nothing when this deployment holds no such database.
     *
     * @throws InvalidArgumentException on an edition the enrichment does not read
     */
    public function path(string $edition): ?string
    {
        $path = $this->pathOf($edition);

        return is_file($path) && is_readable($path) ? $path : null;
    }

    /**
     * The ETag the stored database of that edition was served with, or nothing: this deployment holds no
     * such database, or it was given a file rather than downloaded one.
     *
     * @throws InvalidArgumentException on an edition the enrichment does not read
     */
    public function version(string $edition): ?string
    {
        $version = @file_get_contents($this->pathOf($edition) . '.etag');

        return $version === false || trim($version) === '' ? null : trim($version);
    }

    /**
     * The database of that file stored as the one of its edition, by a copy of the file and never a string
     * of it: the city edition is fifty megabytes, which a string would hold in the memory of the worker
     * (issue #904).
     *
     * @throws InvalidArgumentException on an edition the enrichment does not read
     * @throws RuntimeException when the storage cannot be written
     */
    public function write(string $edition, string $file, ?string $version = null): void
    {
        $path = $this->pathOf($edition);
        if (! is_dir($this->directory) && ! @mkdir($this->directory, 0o700, true) && ! is_dir($this->directory)) {
            throw new RuntimeException(sprintf('The storage of the address databases "%s" cannot be created.', $this->directory));
        }
        $this->put(
            $path,
            static fn (string $temporary): bool => @copy($file, $temporary),
            sprintf('The database "%s" cannot be written to "%s".', $edition, $path),
        );
        // The version is written after the database and taken away when there is none, so what sits beside
        // a database is the version of that database and never of the one before it.
        if ($version === null) {
            @unlink($path . '.etag');

            return;
        }
        $this->put(
            $path . '.etag',
            static fn (string $temporary): bool => @file_put_contents($temporary, $version, LOCK_EX) !== false,
            sprintf('The version of the database "%s" cannot be written.', $edition),
        );
    }

    /**
     * Through a sibling file renamed into place, which is how every file this provider holds is written.
     *
     * @param Closure(string): bool $writes what writes the contents to the sibling file it is given
     *
     * @throws RuntimeException when the file cannot be written
     */
    private function put(string $path, Closure $writes, string $refusal): void
    {
        $temporary = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
        if (! $writes($temporary) || ! @chmod($temporary, 0o600) || ! @rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException($refusal);
        }
    }

    /**
     * @throws InvalidArgumentException on an edition the enrichment does not read
     */
    private function pathOf(string $edition): string
    {
        if (! in_array($edition, self::EDITIONS, true)) {
            throw new InvalidArgumentException(sprintf('"%s" is not an edition the enrichment of a provenance reads.', $edition));
        }

        return $this->directory . '/' . $edition . '.mmdb';
    }
}
