<?php

declare(strict_types=1);

namespace App\Demonstration\Trace;

use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * One call to this provider the demonstration recognises (issue #462): which calls those are, which
 * hops of a picture the call and its answer fill, and which flow and which client the call belongs to.
 *
 * Where the calls are is read from the endpoints of the tenant itself and never written here: a provider
 * that mounts its routes elsewhere is watched where it mounted them. Which flow a call belongs to, is
 * read from the grants the provider is wired with, for the same reason the pictures are.
 *
 * A call the demonstration gains is a class added to the wiring.
 */
interface RecordedEndpointInterface
{
    /**
     * Whether the call this provider served is one of the calls this records: where it was served,
     * what it carried, and what it was answered. A page fetched is not an answer given, and an answer
     * that keeps the browser here is not an answer that was carried to a client.
     */
    public function recognises(Request $request, Response $response, ProviderEndpoints $endpoints): bool;

    /**
     * The flow this call belongs to, read from the wiring, and null when the wiring cannot say: a hop
     * that cannot be attributed is not drawn at all.
     */
    public function flowOf(Request $request, ServedGrantsInterface $served): ?GrantTypeName;

    /**
     * The client this call is made by, and null when the call does not name one: a browser typing a
     * device code names none, and the hop joins the trace of the client that last played the flow.
     */
    public function clientOf(Request $request): ?string;

    /**
     * The hop the call itself fills and the hop its answer fills, either of them null for a call only
     * one half of which is a hop of a picture: the answer that carries an authorization response does
     * not come from the endpoint the request was brought to.
     *
     * @return array{string|null, string|null}
     */
    public function hops(): array;
}
