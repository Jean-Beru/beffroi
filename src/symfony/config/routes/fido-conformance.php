<?php

declare(strict_types=1);

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * The endpoints of the FIDO2 server API the FIDO Conformance Tools drive (architecture §7): not an API of
 * the product, not imported by the routes of the bundle; an application imports this file in development
 * only, under a prefix of its own, to run the tools against its stack.
 */
return static function (RoutingConfigurator $routes): void {
    $routes->import('../../src/Fido/Conformance/', 'attribute');
};
