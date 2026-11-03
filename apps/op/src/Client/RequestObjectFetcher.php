<?php

declare(strict_types=1);

namespace App\Client;

use App\Http\ByteLimit;
use App\Http\Timeout;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\RequestObjectUnavailableException;
use Beffroi\Oidc\Port\RequestObjectFetcherInterface;
use function sprintf;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;

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
    public function __construct(
        private HttpClientInterface $http,
        private Timeout $timeout,
        private ByteLimit $maximumSize,
    ) {
    }

    public function fetch(ClientUri $requestUri): string
    {
        try {
            $response = $this->http->request('GET', $requestUri->value, [
                'headers' => [
                    'Accept' => 'application/oauth-authz-req+jwt, application/jwt',
                ],
                'max_redirects' => 0,
                ...$this->timeout->options(),
            ]);
            $status = $response->getStatusCode();
            if ($status >= 300 && $status < 400) {
                throw new RequestObjectUnavailableException(sprintf(
                    '%s redirects, and no outbound request follows a redirect; publish the request object at the URL that is registered.',
                    $requestUri->value,
                ));
            }
            if ($status < 200 || $status >= 300) {
                throw new RequestObjectUnavailableException(sprintf('%s answered %d.', $requestUri->value, $status));
            }
            $body = '';
            foreach ($this->http->stream($response) as $chunk) {
                $body .= $chunk->getContent();
                if ($this->maximumSize->isExceededBy($body)) {
                    throw new RequestObjectUnavailableException(sprintf(
                        '%s answers more than %d bytes, which no request object needs.',
                        $requestUri->value,
                        $this->maximumSize->bytes,
                    ));
                }
            }

            return $body;
        } catch (RequestObjectUnavailableException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new RequestObjectUnavailableException(sprintf('%s cannot be reached: %s', $requestUri->value, ExceptionTrail::of($exception)), 0, $exception);
        }
    }
}
