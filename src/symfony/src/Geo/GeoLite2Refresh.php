<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Geo;

use function bin2hex;
use DateTimeImmutable;
use function fclose;
use function fopen;
use function fwrite;
use function http_build_query;
use function in_array;
use function is_file;
use function is_readable;
use function random_bytes;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function strlen;
use function sys_get_temp_dir;
use function unlink;
use Beffroi\Core\Exception\InvalidArgumentException;
use MaxMind\Db\Reader;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Throwable;

/**
 * The databases of addresses the enrichment of a provenance reads, brought up to date (architecture §3.5,
 * issue #473): the archive of each edition downloaded, the database taken out of it, opened and refused
 * unless it is an edition this provider reads, then stored where the lane reads it.
 *
 * **What authenticates the source is TLS and the licence key**, and this says so rather than implying
 * more: MaxMind signs nothing, so there is no counterpart here to the root the FIDO metadata blob chains
 * to (`beffroi:webauthn:mds-refresh`). What is checked is the file itself, with the very reader the
 * enrichment will open it with: a database that cannot be opened, or that declares an edition the
 * enrichment does not read, is refused and nothing of it is kept.
 *
 * **It asks before it downloads.** The ETag of what is stored goes out as `If-None-Match`, so a week in
 * which MaxMind published nothing costs one request and no bytes (GeoLite2 is published on Tuesdays).
 *
 * **No archive and no database is held whole in memory** (issue #904): what a source serves is written to
 * a file as it arrives, the database is unpacked from that file into another, the reader opens that one
 * and the storage copies it. The city edition is fifty megabytes unpacked, and its archive decompressed
 * whole goes past the memory PHP gives a worker by default.
 *
 * **No address of this provider leaves it.** What leaves is a request for a file, carrying the licence key
 * of the deployment and nothing of anybody who signed in; what the lane later asks of that file, it asks
 * locally (`GeoLite2GeoLocator`).
 */
final readonly class GeoLite2Refresh
{
    /**
     * Where MaxMind is asked for its databases (https://dev.maxmind.com/geoip/updating-databases): one
     * archive per edition, named by a query string, under the licence key of an account.
     */
    public const string MAXMIND_DOWNLOAD = 'https://download.maxmind.com/app/geoip_download';

    public function __construct(
        private HttpClientInterface $http,
        private GeoLite2Databases $databases,
        private string $licenseKey = '',
    ) {
    }

    /**
     * Every edition the enrichment reads, from MaxMind under the licence key of the deployment, or the
     * sources given instead; nothing at all when there is neither, which is a deployment that enriches no
     * provenance and is told so by whoever asked.
     *
     * @param list<string> $sources an https URL or a file, one archive or one database each
     *
     * @return list<GeoLite2Refreshment>
     */
    public function refresh(array $sources = []): array
    {
        if ($sources === [] && $this->licenseKey === '') {
            return [];
        }
        $refreshments = [];
        foreach ($sources === [] ? $this->maxmind() : $sources as $source) {
            $refreshments[] = $this->one($source);
        }

        return $refreshments;
    }

    private function one(string $source): GeoLite2Refreshment
    {
        $named = self::named($source);
        $edition = self::editionOf($source);
        $downloaded = self::temporary();
        $database = self::temporary();
        try {
            $fetched = $this->fetch($source, $edition === null ? null : $this->databases->version($edition), $downloaded);
            if ($fetched === null) {
                return GeoLite2Refreshment::unchanged($named);
            }
            [$archive, $version] = $fetched;
            GeoLite2Archive::unpack($archive, $database);
            [$declared, $builtOn, $nodes] = self::read($database);
            $this->databases->write($declared, $database, $version);

            return GeoLite2Refreshment::stored($named, $declared, $builtOn, $nodes);
        } catch (Throwable $exception) {
            return GeoLite2Refreshment::refused($named, $exception->getMessage());
        } finally {
            // What was downloaded and what was unpacked are this run's, whatever came of them.
            @unlink($downloaded);
            @unlink($database);
        }
    }

    /**
     * What the database says of itself, read by the reader the enrichment uses.
     *
     * @return array{string, DateTimeImmutable, int}
     *
     * @throws InvalidArgumentException when it cannot be opened, or is not an edition this provider reads
     */
    private static function read(string $database): array
    {
        try {
            $reader = new Reader($database);
            $metadata = $reader->metadata();
            $reader->close();
        } catch (Throwable $exception) {
            throw new InvalidArgumentException(sprintf('the database cannot be opened (%s)', $exception->getMessage()), previous: $exception);
        }
        if (! in_array($metadata->databaseType, GeoLite2Databases::EDITIONS, true)) {
            throw new InvalidArgumentException(sprintf(
                'it is a "%s" database, which the enrichment of a provenance does not read',
                $metadata->databaseType,
            ));
        }

        return [$metadata->databaseType, new DateTimeImmutable('@' . $metadata->buildEpoch), $metadata->nodeCount];
    }

    /**
     * The archive as a file of this host and the version it was served with, or nothing when the source
     * answers that what is stored is what it serves: a file is read where it is, and what an https source
     * serves is written to the file given as it arrives. No outbound request follows a redirect (decision
     * 0006): the URL the source names is said instead.
     *
     * @return array{string, ?string}|null
     *
     * @throws InvalidArgumentException when the source cannot be read
     */
    private function fetch(string $source, ?string $version, string $into): ?array
    {
        if (! str_starts_with($source, 'https://')) {
            // A file, and nothing a stream wrapper would go and fetch: what reaches the network reaches
            // it through the client above, where a redirect is not followed (decision 0006).
            if (! is_file($source)) {
                throw new InvalidArgumentException('it is neither an https URL nor a file of this host');
            }

            return is_readable($source) ? [$source, null] : throw new InvalidArgumentException('the file cannot be read');
        }
        try {
            $response = $this->requested($source, $version);
            $status = $response->getStatusCode();
            if ($status === 304) {
                return null;
            }
            if ($status >= 300 && $status < 400) {
                $location = $response->getHeaders(false)['location'][0] ?? '?';
                throw new InvalidArgumentException(sprintf(
                    'the source redirects to %s, and no outbound request follows a redirect; name that URL instead',
                    $location,
                ));
            }
            if ($status !== 200) {
                throw new InvalidArgumentException(sprintf('the source answered %d', $status));
            }
            $this->written($response, $into);

            return [$into, $response->getHeaders(false)['etag'][0] ?? null];
        } catch (InvalidArgumentException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new InvalidArgumentException(sprintf('the source cannot be reached: %s', $exception->getMessage()), previous: $exception);
        }
    }

    /**
     * One GET, the version of what is stored going out with it, and no redirect followed (decision 0006).
     */
    private function requested(string $url, ?string $version): ResponseInterface
    {
        return $this->http->request('GET', $url, [
            'headers' => $version === null
                ? []
                : [
                    'If-None-Match' => $version,
                ],
            'max_redirects' => 0,
            'buffer' => false,
        ]);
    }

    /**
     * What the response serves, written to that file as it arrives.
     *
     * @throws InvalidArgumentException when the file cannot be written
     */
    private function written(ResponseInterface $response, string $into): void
    {
        $file = @fopen($into, 'wb');
        if ($file === false) {
            throw new InvalidArgumentException('the archive cannot be written where it is downloaded');
        }
        try {
            foreach ($this->http->stream($response) as $chunk) {
                $content = $chunk->getContent();
                if (@fwrite($file, $content) !== strlen($content)) {
                    throw new InvalidArgumentException('the archive cannot be written where it is downloaded');
                }
            }
        } finally {
            fclose($file);
        }
    }

    /**
     * A file of the temporary directory of this host for one run, named so that two runs never meet.
     */
    private static function temporary(): string
    {
        return sys_get_temp_dir() . '/beffroi-geoip-' . bin2hex(random_bytes(8));
    }

    /**
     * The archive of every edition the enrichment reads, at MaxMind, under the licence key of the
     * deployment.
     *
     * @return list<string>
     */
    private function maxmind(): array
    {
        $sources = [];
        foreach (GeoLite2Databases::EDITIONS as $edition) {
            $sources[] =
                self::MAXMIND_DOWNLOAD
                . '?'
                . http_build_query([
                    'edition_id' => $edition,
                    'license_key' => $this->licenseKey,
                    'suffix' => 'tar.gz',
                ]);
        }

        return $sources;
    }

    /**
     * Which edition a source serves, when the source says so: what the ETag of a stored database may be
     * compared with is the version of that same edition, so a source that names none is downloaded.
     */
    private static function editionOf(string $source): ?string
    {
        foreach (GeoLite2Databases::EDITIONS as $edition) {
            if (str_contains($source, $edition)) {
                return $edition;
            }
        }

        return null;
    }

    /**
     * A source as a line of output may name it, which is a URL without the licence key of the deployment:
     * what a console writes is read again in a log, in a terminal history and over a shoulder.
     */
    private static function named(string $source): string
    {
        if (! str_starts_with($source, self::MAXMIND_DOWNLOAD)) {
            return $source;
        }
        $edition = self::editionOf($source);

        return self::MAXMIND_DOWNLOAD . ($edition === null ? '' : '?edition_id=' . $edition);
    }
}
