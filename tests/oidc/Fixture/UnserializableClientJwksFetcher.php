<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Closure;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Port\ClientJwksFetcherInterface;

/**
 * A reader of "jwks_uri" that cannot be written to a queue, which is what the one of a deployment is: it
 * is an HTTP client, decorated by the framework, and a decorator holds a closure. Nothing here reads a
 * key; what it is for is to fail loudly the day something that leaves the process reaches a client
 * again (architecture §5.6).
 */
final class UnserializableClientJwksFetcher implements ClientJwksFetcherInterface
{
    public Closure $decorated;

    public function __construct()
    {
        $this->decorated = static fn (): bool => true;
    }

    public function fetch(ClientUri $jwksUri): ClientJwks
    {
        throw new ClientKeysUnavailableException('This reader answers nothing; it is here to be serialized, or rather not to be.');
    }
}
