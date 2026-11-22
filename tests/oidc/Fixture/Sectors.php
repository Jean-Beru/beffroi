<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Claims\Sector\JwksUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\Sector\RedirectUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\Sector\RegisteredSectorIdentifier;
use Beffroi\Oidc\Application\Claims\SectorIdentifiers;

/**
 * OIDC Core §8.1, CIBA Core §4
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
