<?php

declare(strict_types=1);

namespace Heidi\Bundle\Plane;

use function str_starts_with;

/**
 * The plane a process serves (architecture §5.2, §6). Every route of the bundle carries its plane in its
 * name: "heidi_interaction_*" is what the browser of the user calls (authorize, login, consent, logout),
 * "heidi_protocol_*" what the relying parties call server to server (discovery, jwks, token, userinfo,
 * introspection, revocation).
 * A process dedicated to one plane refuses the routes of the other with a 404, so that a flood on the
 * login cannot take "/token" and "/jwks" down with it, and a protocol process cannot be diverted to the
 * login. Read from HEIDI_PLANE; "all" serves both, which is what development and a single process do.
 */
enum Plane: string
{
    case All = 'all';
    case Interaction = 'interaction';
    case Protocol = 'protocol';

    public const string INTERACTION_ROUTE_PREFIX = 'heidi_interaction_';

    public const string PROTOCOL_ROUTE_PREFIX = 'heidi_protocol_';

    /**
     * Whether this plane serves the named route. A route that is not one of the bundle's, whatever
     * its name, belongs to the host application and is never refused here.
     */
    public function serves(string $routeName): bool
    {
        return match ($this) {
            self::All => true,
            self::Interaction => ! str_starts_with($routeName, self::PROTOCOL_ROUTE_PREFIX),
            self::Protocol => ! str_starts_with($routeName, self::INTERACTION_ROUTE_PREFIX),
        };
    }
}
