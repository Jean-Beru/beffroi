<?php

declare(strict_types=1);

namespace App\Plane;

use function str_starts_with;

/**
 * The plane a process serves, read from BEFFROI_PLANE (architecture §5.2, §6): every route of the provider
 * carries its plane in its name, and a process dedicated to one refuses the routes of the other with a 404.
 */
enum Plane: string
{
    case All = 'all';
    case Interaction = 'interaction';
    case Protocol = 'protocol';

    public const string INTERACTION_ROUTE_PREFIX = 'beffroi_interaction_';

    public const string PROTOCOL_ROUTE_PREFIX = 'beffroi_protocol_';

    /**
     * The plane a route belongs to, read from its name, and null for a route that is not one of the two
     * planes: a route of the application, and the endpoints a conformance tool drives, which belong
     * to no plane and to no environment but dev. What answers by plane reads this and holds no list of
     * routes, so that a route the provider gains is covered by being routed.
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
     * A route that is not one of the provider's is never refused, and a process that serves every plane
     * refuses nothing. The convention that a name carries its plane is read once, above.
     */
    public function serves(string $routeName): bool
    {
        $plane = self::ofRoute($routeName);

        return $plane === null || $this === self::All || $plane === $this;
    }
}
