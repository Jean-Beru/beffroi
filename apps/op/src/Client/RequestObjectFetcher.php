<?php

declare(strict_types=1);

namespace App\Client;

use App\Http\BoundedRead;
use App\Http\ByteLimit;
use App\Http\ReadRefusedException;
use App\Http\ReadWords;
use App\Http\Timeout;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\RequestObjectUnavailableException;
use Beffroi\Oidc\Port\RequestObjectFetcherInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Reads back the request object a client publishes behind its "request_uri" (RFC 9101 §5.2, OIDC Core
 * §6.2): one GET, no cookie, no authentication, nothing sent but the request. No redirect is followed
 * (decision 0006): a "request_uri" names where the object is, and the provider does not let a third
 * party move it. The body is read in chunks and the read stops as soon as it is longer than a request
 * object has any reason to be, and the timeout is the fetcher's own, because the browser of a user is
 * waiting on this one: a client that hangs must not hold a worker.
 *
 * Nothing of the answer is trusted here, not even its content type: what comes back is a string, and
 * whether it is a request object this client signed is the resolver's to say.
 */
final readonly class RequestObjectFetcher implements RequestObjectFetcherInterface
{
    private BoundedRead $reading;

    public function __construct(
        HttpClientInterface $http,
        Timeout $timeout,
        ByteLimit $maximumSize,
    ) {
        $this->reading = new BoundedRead($http, $timeout, $maximumSize);
    }

    public function fetch(ClientUri $requestUri): string
    {
        try {
            return $this->reading->read($requestUri->value, 'application/oauth-authz-req+jwt, application/jwt', new ReadWords(
                'publish the request object at the URL that is registered.',
                '%s answers more than %d bytes, which no request object needs.',
            ));
        } catch (ReadRefusedException $exception) {
            throw new RequestObjectUnavailableException($exception->getMessage(), 0, $exception->getPrevious());
        }
    }
}
