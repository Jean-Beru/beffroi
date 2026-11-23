<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Oidc\Application\Claims\Sector\IdentifiersWithoutARedirection;
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
        $withoutARedirection = self::withoutARedirection();

        return new SectorIdentifiers([
            new RegisteredSectorIdentifier(),
            new RedirectUriSectorIdentifier($withoutARedirection),
            new JwksUriSectorIdentifier($withoutARedirection),
        ]);
    }

    /**
     * RFC 8628 §3.4, CIBA Core §10.1
     */
    public static function withoutARedirection(): IdentifiersWithoutARedirection
    {
        return new IdentifiersWithoutARedirection(Grants::servedWithEveryWayOfAskingThePerson());
    }
}
