<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Exception\ClientKeysUnavailableException;
use Heidi\Oidc\Port\ClientJwksFetcherInterface;
use function sprintf;

/**
 * The RS256 pair `ClientAssertions` publishes, answered behind the one URI a test names and behind no
 * other: a client that registered a "jwks_uri" rather than an inline "jwks", read back the way a
 * deployment reads it.
 *
 * It takes no arguments, which is what lets a kernel wire it in place of the fetcher that makes a real
 * request (`FakeClientJwksFetcher` is the one a unit test drives, answer by answer). Every other URI is
 * unavailable, because nothing in a test publishes keys anywhere else: a client whose keys this answered
 * by accident would be authenticated by keys it never registered. Never leaves the test suite.
 */
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
