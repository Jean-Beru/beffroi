<?php

declare(strict_types=1);

namespace Heidi\Bundle\Plane;

use function str_starts_with;

/**
 * The plane a process serves, read from HEIDI_PLANE (architecture §5.2, §6): every route of the bundle
 * carries its plane in its name, and a process dedicated to one refuses the routes of the other with a 404.
 */
enum Plane: string
{
    case All = 'all';
    case Interaction = 'interaction';
    case Protocol = 'protocol';

    public const string INTERACTION_ROUTE_PREFIX = 'heidi_interaction_';

    public const string PROTOCOL_ROUTE_PREFIX = 'heidi_protocol_';

    /**
     * The plane a route belongs to, read from its name, and null for a route that is not one of the two
     * planes: a route of the host application, and the endpoints of the FIDO conformance tools, which
     * belong to no plane and to no environment but dev. What answers by plane reads this and holds no
     * list of routes, so that a route the bundle gains is covered by being routed.
     */
    public static function ofRoute(string $routeName): ?self
    {
        return match (true) {
            str_starts_with($routeName, self::INTERACTION_ROUTE_PREFIX) => self::Interaction,
            str_starts_with($routeName, self::PROTOCOL_ROUTE_PREFIX) => self::Protocol,
            default => null,
        };
    }

    /**
     * A route that is not one of the bundle's is never refused, and a process that serves every plane
     * refuses nothing. The convention that a name carries its plane is read once, above.
     */
    public function serves(string $routeName): bool
    {
        $plane = self::ofRoute($routeName);

        return $plane === null || $this === self::All || $plane === $this;
    }
}
