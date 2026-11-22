<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\RequestObjectUnavailableException;
use Beffroi\Oidc\Port\RequestObjectFetcherInterface;

final class FakeRequestObjectFetcher implements RequestObjectFetcherInterface
{
    /**
     * @var list<ClientUri>
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
