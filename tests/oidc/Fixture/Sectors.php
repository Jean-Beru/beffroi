<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Claims\Sector\JwksUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\Sector\RedirectUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\Sector\RegisteredSectorIdentifier;
use Beffroi\Oidc\Application\Claims\SectorIdentifiers;

/**
 * The ways a client may say which sector it is of, wired as a deployment wires them (OIDC Core §8.1,
 * CIBA Core §4): the URI it registered to say so first, then the host of its redirection URIs, then, for
 * a client that registers none, its "jwks_uri".
 */
final class Sectors
{
    public static function ofAProvider(): SectorIdentifiers
    {
        return new SectorIdentifiers([
            new RegisteredSectorIdentifier(),
            new RedirectUriSectorIdentifier(),
            new JwksUriSectorIdentifier(),
        ]);
    }
}
