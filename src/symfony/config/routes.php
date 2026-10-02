<?php

declare(strict_types=1);

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * The routes of the bundle (architecture §5.2), declared on the controllers; an application imports this
 * file under the path of its issuer. Every route name carries its plane, which is what BEFFROI_PLANE reads.
 */
return static function (RoutingConfigurator $routes): void {
    $routes->import('../src/Controller/', 'attribute');
};
