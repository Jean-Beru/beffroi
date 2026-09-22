<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;

/**
 * What the authorization endpoint reads before it judges anything: the parameters of the request,
 * whichever of the three ways in carried them.
 */
interface AuthorizationRequestReaderInterface
{
    /**
     * @throws OAuth2Exception never redirectable: what a request that was pushed or signed names as its
     *                         destination is inside what the provider has just refused to read
     */
    public function read(Tenant $tenant, Request $request): ReceivedAuthorizationRequest;
}
