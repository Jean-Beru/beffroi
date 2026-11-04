<?php

declare(strict_types=1);

namespace App\Client;

use App\Http\BoundedRead;
use App\Http\ByteLimit;
use App\Http\ReadRefusedException;
use App\Http\ReadWords;
use App\Http\Timeout;
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
 * Reads back the JWK Set a client publishes (RFC 7591 §2): one GET, no cookie, no authentication,
 * nothing sent but the request. No redirect is followed (decision 0006): a "jwks_uri" names where the
 * keys are, and the provider does not let a third party move them. The body is read in chunks and the
 * read stops as soon as it is longer than a JWK Set has any reason to be, and the timeout is the
 * fetcher's own, because a client that hangs must not hold a worker: an endpoint authenticating a client
 * is waiting on this.
 */
final readonly class ClientJwksFetcher implements ClientJwksFetcherInterface
{
    private BoundedRead $reading;

    public function __construct(
        HttpClientInterface $http,
        Timeout $timeout,
        ByteLimit $maximumSize,
    ) {
        $this->reading = new BoundedRead($http, $timeout, $maximumSize);
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
            return $this->reading->read($jwksUri->value, 'application/json', new ReadWords(
                'publish the keys at the URL that is registered.',
                '%s answers more than %d bytes, which no JWK Set needs.',
            ));
        } catch (ReadRefusedException $exception) {
            throw new ClientKeysUnavailableException($exception->getMessage(), 0, $exception->getPrevious());
        }
    }
}
