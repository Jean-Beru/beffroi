<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Client\ClientJwks;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Exception\ClientKeysUnavailableException;
use Beffroi\Oidc\Port\ClientJwksFetcherInterface;
use function sprintf;

final readonly class ClientKeysBehindAJwksUri implements ClientJwksFetcherInterface
{
    public const string JWKS_URI = 'https://registered.test/jwks.json';

    public function fetch(ClientUri $jwksUri): ClientJwks
    {
        if ($jwksUri->value !== self::JWKS_URI) {
            throw new ClientKeysUnavailableException(sprintf('Nothing of the tests publishes keys behind "%s".', $jwksUri->value));
        }

        return ClientAssertions::publishedKeys(Algorithms::rs256());
    }
}
