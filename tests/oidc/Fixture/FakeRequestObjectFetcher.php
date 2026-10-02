<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\RequestObjectUnavailableException;
use Beffroi\Oidc\Port\RequestObjectFetcherInterface;

/**
 * A "request_uri" that answers what the test told it to, and records what was read. A fetcher that was
 * never called is what proves that an unregistered URL costs no outbound request. Never leaves the test
 * suite.
 */
final class FakeRequestObjectFetcher implements RequestObjectFetcherInterface
{
    /**
     * @var list<ClientUri> the URLs read, in order
     */
    public private(set) array $fetched = [];

    public ?RequestObjectUnavailableException $failure = null;

    public function __construct(
        private readonly string $answer = '',
    ) {
    }

    public function fetch(ClientUri $requestUri): string
    {
        $this->fetched[] = $requestUri;
        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->answer;
    }
}
