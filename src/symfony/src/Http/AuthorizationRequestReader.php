<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Application\Authorization\RequestObjectResolver;
use Beffroi\Oidc\Application\PushedAuthorization\PushedAuthorizationRequestResolver;
use Symfony\Component\HttpFoundation\Request;

/**
 * The two resolvers of the authorization endpoint, in the one order the protocol gives them. A request
 * the client pushed is read from the record and not from the query, which carries nothing but the client
 * and the reference to it (RFC 9126 §4); a request carried in a JWT is read before anything of the query
 * is, the object deciding the parameters of the request and the query nothing but which client signed it
 * (RFC 9101 §6.1). A pushed request was read at the endpoint it was pushed to and carries no object.
 *
 * The order is a rule of the protocol and not of a controller, so it is written here once, for the
 * endpoint and for whoever wants to know how a request reached it.
 */
final readonly class AuthorizationRequestReader implements AuthorizationRequestReaderInterface
{
    public function __construct(
        private PushedAuthorizationRequestResolver $pushedRequests,
        private RequestObjectResolver $requestObjects,
        private RequestContextFactory $contexts,
    ) {
    }

    public function read(Tenant $tenant, Request $request): ReceivedAuthorizationRequest
    {
        $parameters = RequestParameters::ofBrowserRequest($request);
        $pushed = $this->pushedRequests->resolve($tenant, $parameters, $this->contexts->fromRequest($request));
        $parameters = $pushed === null ? $parameters : PushedAuthorizationRequestResolver::parametersOf($pushed);
        $object = $this->requestObjects->resolve($tenant, $parameters);

        // A request object the client signed was read at the endpoint it pushed to, and the record is
        // what answers for it here (RFC 9126 §4): what carried the request is the record's to say.
        return new ReceivedAuthorizationRequest(
            $object->parameters ?? $parameters,
            $pushed !== null,
            $object !== null || ($pushed->carriedBySignedObject ?? false),
            $pushed?->requestUriHash,
        );
    }
}
