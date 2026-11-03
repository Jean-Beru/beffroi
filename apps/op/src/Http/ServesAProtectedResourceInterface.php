<?php

declare(strict_types=1);

namespace App\Http;

/**
 * What a controller of a protected resource of the provider declares (OIDC Core §5.3, architecture
 * §4.7): an endpoint a caller reaches by presenting an access token, and not one where a client
 * authenticates. Its answers name the exchange they belong to (`FapiInteractionId`, FAPI 1.0 Advanced
 * Final §6.2.1), served or refused.
 *
 * A resource the provider gains carries what a resource owes by declaring itself one, so nothing holds a
 * list of the routes that are resources, as nothing holds a list of the routes of a plane.
 */
interface ServesAProtectedResourceInterface
{
}
