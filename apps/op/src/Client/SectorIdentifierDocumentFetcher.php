<?php

declare(strict_types=1);

namespace App\Client;

use App\Http\ByteLimit;
use App\Http\Timeout;
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
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * OIDC Registration §5
 *
 * No redirect is followed: a redirect would let a third party answer for the host of the sector.
 */
final readonly class SectorIdentifierDocumentFetcher implements SectorIdentifierDocumentFetcherInterface
{
    public function __construct(
        private HttpClientInterface $http,
        private Timeout $timeout,
        private ByteLimit $maximumSize,
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
                ...$this->timeout->options(),
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
                if ($this->maximumSize->isExceededBy($body)) {
                    throw new SectorIdentifierUnavailableException(sprintf(
                        '%s answers more than %d bytes, which no list of redirection URIs needs.',
                        $sectorIdentifierUri->value,
                        $this->maximumSize->bytes,
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
