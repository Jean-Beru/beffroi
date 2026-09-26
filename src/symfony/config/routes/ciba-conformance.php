<?php

declare(strict_types=1);

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * The endpoint the OpenID conformance suite answers a backchannel request with when nobody is there to
 * answer it (architecture §7, "automated_ciba_approval_url"): not an API of the product, not imported by
 * the routes of the bundle; an application imports this file in development only, under a prefix of its
 * own, to run the FAPI-CIBA plan against its stack.
 */
return static function (RoutingConfigurator $routes): void {
    $routes->import('../../src/Ciba/Conformance/', 'attribute');
};
