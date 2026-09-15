<?php

declare(strict_types=1);

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * The routes of the bundle (architecture §5.2), declared on the controllers. An application imports this
 * file, under the path of its issuer when the issuer carries one:
 *
 *     heidi:
 *         resource: '@HeidiBundle/config/routes.php'
 *
 * Every route name carries its plane, "heidi_interaction_*" or "heidi_protocol_*", which is what
 * HEIDI_PLANE reads.
 */
return static function (RoutingConfigurator $routes): void {
    $routes->import('../src/Controller/', 'attribute');
};
