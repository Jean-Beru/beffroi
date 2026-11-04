<?php

declare(strict_types=1);

namespace App\Plane;

use function str_starts_with;

/**
 * The plane a process serves, read from BEFFROI_PLANE; every route of the provider carries its plane in its name.
 */
enum Plane: string
{
    case All = 'all';
    case Interaction = 'interaction';
    case Protocol = 'protocol';

    public const string INTERACTION_ROUTE_PREFIX = 'beffroi_interaction_';

    public const string PROTOCOL_ROUTE_PREFIX = 'beffroi_protocol_';

    public static function ofRoute(string $routeName): ?self
    {
        return match (true) {
            str_starts_with($routeName, self::INTERACTION_ROUTE_PREFIX) => self::Interaction,
            str_starts_with($routeName, self::PROTOCOL_ROUTE_PREFIX) => self::Protocol,
            default => null,
        };
    }

    public function serves(string $routeName): bool
    {
        $plane = self::ofRoute($routeName);

        return $plane === null || $this === self::All || $plane === $this;
    }
}
