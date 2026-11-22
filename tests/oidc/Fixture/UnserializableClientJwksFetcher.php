<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Closure;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;

/**
 * Architecture §5.6
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
