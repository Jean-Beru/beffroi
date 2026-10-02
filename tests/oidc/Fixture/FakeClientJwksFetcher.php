<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use function count;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;

/**
 * A "jwks_uri" that answers what the test told it to, one answer per read, and counts the reads. Never
 * leaves the test suite.
 */
final class FakeClientJwksFetcher implements ClientJwksFetcherInterface
{
    /**
     * @var list<ClientUri> the URIs read, in order
     */
    public private(set) array $fetched = [];

    public ?ClientKeysUnavailableException $failure = null;

    /**
     * @param list<ClientJwks> $answers the sets it answers, in order; the last one is answered again
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
