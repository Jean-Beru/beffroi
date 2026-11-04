<?php

declare(strict_types=1);

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * The routes of the provider (architecture §5.2), declared on the controllers; the application imports this
 * file at the root, the issuer of a tenant being an origin (TenantFactory). Every route name carries its plane, which is what BEFFROI_PLANE reads.
 */
return static function (RoutingConfigurator $routes): void {
    $routes->import('../../src/Controller/', 'attribute');
};
