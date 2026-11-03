<?php

declare(strict_types=1);

namespace App\Geo;

use function bin2hex;
use DateTimeImmutable;
use function fclose;
use function fopen;
use function fwrite;
use function http_build_query;
use function in_array;
use function is_file;
use function is_readable;
use function preg_replace;
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
 * **It asks before it downloads.** The ETag of what is stored goes out as `If-None-Match`, and the storage
 * MaxMind redirects its downloads to answers it, so a run that finds the version it keeps costs a redirect
 * and an answer that nothing changed, and no byte of the database. MaxMind publishes the city edition on
 * Tuesdays and Fridays and the ASN edition every weekday ("Download and update databases",
 * https://support.maxmind.com/knowledge-base/articles/download-and-update-maxmind-databases).
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

    /**
     * Where MaxMind keeps the archives it serves, and the one origin an outbound request of this provider
     * follows a redirect to (decision 0032): MaxMind answers every download with a redirect to a presigned
     * URL of R2, the storage of Cloudflare, "using HTTPS on the following hostname"
     * (https://dev.maxmind.com/geoip/updating-databases). The redirect is followed once, from a download of
     * MaxMind, to a URL that starts with this.
     */
    public const string MAXMIND_STORAGE = 'https://mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com/';

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
            return GeoLite2Refreshment::refused($named, self::withoutQueries($exception->getMessage()));
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
     * 0006) but one, from a download of MaxMind to its storage, once (decision 0032).
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
            if (self::redirects($response)) {
                $response = $this->requested(self::followed($source, self::location($response)), $version);
                if (self::redirects($response)) {
                    throw new InvalidArgumentException(sprintf(
                        'the storage of MaxMind redirects again, to %s, and no outbound request follows a second redirect',
                        self::location($response),
                    ));
                }
            }
            $status = $response->getStatusCode();
            if ($status === 304) {
                return null;
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
     * One GET, the version of what is stored going out with it, and no redirect followed by the client:
     * the one this provider follows, it follows itself.
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
     * Where a redirect of that source leads, when it is the one redirect an outbound request follows
     * (decision 0032): a download of MaxMind, to its storage, over https.
     *
     * @throws InvalidArgumentException on any other redirect, naming where it leads
     */
    private static function followed(string $source, string $location): string
    {
        if (! str_starts_with($source, self::MAXMIND_DOWNLOAD . '?')) {
            throw new InvalidArgumentException(sprintf(
                'the source redirects to %s, and no outbound request follows a redirect; name that URL instead',
                $location,
            ));
        }
        if (! str_starts_with($location, self::MAXMIND_STORAGE)) {
            throw new InvalidArgumentException(sprintf(
                'MaxMind redirects to %s rather than to %s, the one redirect an outbound request follows',
                $location,
                self::MAXMIND_STORAGE,
            ));
        }

        return $location;
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

    private static function redirects(ResponseInterface $response): bool
    {
        $status = $response->getStatusCode();

        return $status >= 300 && $status < 400 && $status !== 304;
    }

    private static function location(ResponseInterface $response): string
    {
        return $response->getHeaders(false)['location'][0] ?? '?';
    }

    /**
     * The reason of a refusal with the query of every URL it names withheld, "?..." in its place: the
     * licence key of a download of MaxMind and the signature of a presigned URL travel there, a refusal is
     * written to a console and to a log, and the reason a client of HTTP gives names the URL it could not
     * read whole. What follows a URL, a parenthesis, a comma or a period, stays.
     */
    private static function withoutQueries(string $reason): string
    {
        return preg_replace('~(https?://[^\s"\'<>?#]*)([?#])[^\s"\'<>]*?(?=[.,;:)\]]*(?:[\s"\'<>]|$))~', '$1$2...', $reason) ?? $reason;
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
