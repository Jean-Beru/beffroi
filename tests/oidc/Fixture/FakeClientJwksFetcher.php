<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function count;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;

final class FakeClientJwksFetcher implements ClientJwksFetcherInterface
{
    /**
     * @var list<ClientUri>
     */
    public private(set) array $fetched = [];

    public ?ClientKeysUnavailableException $failure = null;

    /**
     * @param list<ClientJwks> $answers in order, the last one answered again
     */
    public function __construct(
        private array $answers,
    ) {
    }

    public function fetch(ClientUri $jwksUri): ClientJwks
    {
        $this->fetched[] = $jwksUri;
        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->answers[count($this->fetched) - 1] ?? $this->answers[count($this->answers) - 1];
    }
}
