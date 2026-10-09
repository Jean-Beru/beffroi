<?php

declare(strict_types=1);

namespace App\Demonstration\Trace\Endpoint;

use App\Demonstration\Trace\NamedClient;
use App\Demonstration\Trace\RecordedEndpointInterface;
use Beffroi\Oidc\Application\Flow\TheUserIsSentToTheClient;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Where a browser brings an authorization request (RFC 6749 §3.1) and is answered one. Both halves are
 * hops of the picture of the flow that sends the user back to the client.
 */
final readonly class TheAuthorizationEndpoint implements RecordedEndpointInterface
{
    public function recognises(Request $request, Response $response, ProviderEndpoints $endpoints): bool
    {
        return ServedAt::is($request, $endpoints->authorization);
    }

    public function flowOf(Request $request, ServedGrantsInterface $served): ?GrantTypeName
    {
        return OneFlowOfTheWiring::of($served->sendingTheUserToTheClient());
    }

    public function clientOf(Request $request): ?string
    {
        return NamedClient::of($request);
    }

    public function hops(): array
    {
        // the answer that carries the authorization response is recorded by the answer that leaves,
        // wherever the interaction ended: a request parked at a login is answered from a page
        return [TheUserIsSentToTheClient::AUTHORIZATION_REQUEST, null];
    }
}
