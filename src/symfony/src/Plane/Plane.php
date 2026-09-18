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
     * A route that is not one of the bundle's is never refused.
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
