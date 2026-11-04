<?php

declare(strict_types=1);

namespace App\Client;

use App\Http\ByteLimit;
use App\Http\Timeout;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;
use function is_array;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use function sprintf;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

/**
 * Follows no redirect, reads the body up to a bound and times out on its own: a hanging client holds no worker.
 */
final readonly class ClientJwksFetcher implements ClientJwksFetcherInterface
{
    public function __construct(
        private HttpClientInterface $http,
        private Timeout $timeout,
        private ByteLimit $maximumSize,
    ) {
    }

    public function fetch(ClientUri $jwksUri): ClientJwks
    {
        $body = $this->read($jwksUri);
        try {
            $document = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $exception) {
            throw new ClientKeysUnavailableException(sprintf('%s does not answer JSON.', $jwksUri->value), 0, $exception);
        }
        if (! is_array($document)) {
            throw new ClientKeysUnavailableException(sprintf('%s does not answer a JWK Set.', $jwksUri->value));
        }
        try {
            return ClientJwks::fromDocument($document);
        } catch (InvalidArgumentException $exception) {
            throw new ClientKeysUnavailableException(sprintf('%s does not answer a JWK Set: %s', $jwksUri->value, $exception->getMessage()), 0, $exception);
        }
    }

    /**
     * @throws ClientKeysUnavailableException
     */
    private function read(ClientUri $jwksUri): string
    {
        try {
            $response = $this->http->request('GET', $jwksUri->value, [
                'headers' => [
                    'Accept' => 'application/json',
                ],
                'max_redirects' => 0,
                ...$this->timeout->options(),
            ]);
            $status = $response->getStatusCode();
            if ($status >= 300 && $status < 400) {
                throw new ClientKeysUnavailableException(sprintf(
                    '%s redirects, and no outbound request follows a redirect; publish the keys at the URL that is registered.',
                    $jwksUri->value,
                ));
            }
            if ($status < 200 || $status >= 300) {
                throw new ClientKeysUnavailableException(sprintf('%s answered %d.', $jwksUri->value, $status));
            }
            $body = '';
            foreach ($this->http->stream($response) as $chunk) {
                $body .= $chunk->getContent();
                if ($this->maximumSize->isExceededBy($body)) {
                    throw new ClientKeysUnavailableException(sprintf(
                        '%s answers more than %d bytes, which no JWK Set needs.',
                        $jwksUri->value,
                        $this->maximumSize->bytes,
                    ));
                }
            }

            return $body;
        } catch (ClientKeysUnavailableException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new ClientKeysUnavailableException(sprintf('%s cannot be reached: %s', $jwksUri->value, ExceptionTrail::of($exception)), 0, $exception);
        }
    }
}
