<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Client;

use function array_is_list;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\SectorIdentifierUnavailableException;
use Beffroi\Oidc\Port\SectorIdentifierDocumentFetcherInterface;
use function is_array;
use function is_string;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use function sprintf;
use function strlen;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * Reads back the document a client publishes behind its "sector_identifier_uri" (OIDC Registration §5): one
 * GET, no cookie, no authentication, nothing sent but the request. No redirect is followed (decision 0006):
 * the document proves that whoever registers controls the host of the sector, and a redirect would let a
 * third party answer for that host. The body is read in chunks and the read stops as soon as it is longer
 * than a list of redirection URIs has any reason to be, and the timeout is the fetcher's own, because a
 * client that hangs must not hold a worker: a registration is waiting on this.
 *
 * What comes back is a JSON array of strings and nothing else. A document that is an object, or an array
 * holding anything but strings, is not the document §5 describes, and a registration is refused rather than
 * checked against half of one.
 */
final readonly class SectorIdentifierDocumentFetcher implements SectorIdentifierDocumentFetcherInterface
{
    public function __construct(
        private HttpClientInterface $http,
        private float $timeout,
        private int $maximumSize,
    ) {
    }

    public function fetch(ClientUri $sectorIdentifierUri): array
    {
        $body = $this->read($sectorIdentifierUri);
        try {
            $document = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        } catch (Throwable $exception) {
            throw new SectorIdentifierUnavailableException(sprintf('%s does not answer JSON.', $sectorIdentifierUri->value), 0, $exception);
        }
        if (! is_array($document) || ! array_is_list($document)) {
            throw new SectorIdentifierUnavailableException(sprintf(
                '%s does not answer the JSON array of redirection URIs of OIDC Registration section 5.',
                $sectorIdentifierUri->value,
            ));
        }
        $redirectUris = [];
        foreach ($document as $value) {
            if (! is_string($value)) {
                throw new SectorIdentifierUnavailableException(sprintf(
                    '%s answers an array holding something that is not a redirection URI (OIDC Registration section 5).',
                    $sectorIdentifierUri->value,
                ));
            }
            $redirectUris[] = $value;
        }

        return $redirectUris;
    }

    /**
     * @throws SectorIdentifierUnavailableException
     */
    private function read(ClientUri $sectorIdentifierUri): string
    {
        try {
            $response = $this->http->request('GET', $sectorIdentifierUri->value, [
                'headers' => [
                    'Accept' => 'application/json',
                ],
                'max_redirects' => 0,
                'timeout' => $this->timeout,
                'max_duration' => $this->timeout,
            ]);
            $status = $response->getStatusCode();
            if ($status >= 300 && $status < 400) {
                throw new SectorIdentifierUnavailableException(sprintf(
                    '%s redirects, and no outbound request follows a redirect; publish the document at the URL that is registered.',
                    $sectorIdentifierUri->value,
                ));
            }
            if ($status < 200 || $status >= 300) {
                throw new SectorIdentifierUnavailableException(sprintf('%s answered %d.', $sectorIdentifierUri->value, $status));
            }
            $body = '';
            foreach ($this->http->stream($response) as $chunk) {
                $body .= $chunk->getContent();
                if (strlen($body) > $this->maximumSize) {
                    throw new SectorIdentifierUnavailableException(sprintf(
                        '%s answers more than %d bytes, which no list of redirection URIs needs.',
                        $sectorIdentifierUri->value,
                        $this->maximumSize,
                    ));
                }
            }

            return $body;
        } catch (SectorIdentifierUnavailableException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new SectorIdentifierUnavailableException(
                sprintf('%s cannot be reached: %s', $sectorIdentifierUri->value, ExceptionTrail::of($exception)),
                0,
                $exception,
            );
        }
    }
}
