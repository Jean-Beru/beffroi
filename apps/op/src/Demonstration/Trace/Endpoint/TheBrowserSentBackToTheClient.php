<?php

declare(strict_types=1);

namespace App\Demonstration\Trace\Endpoint;

use App\Demonstration\Trace\RecordedEndpointInterface;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Oidc\Application\Flow\TheUserIsSentToTheClient;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Where an authorization response really comes from (RFC 6749 §4.1.2): the answer that sends the browser
 * away from this provider, which is the authorization endpoint when the request needed nothing of the
 * user, and the page the interaction ended on when it did, a login, a consent, a code typed.
 *
 * It is recognised by what it is and not by where it is served, because where it is served is whichever
 * page the user was last on. What narrows it to an authorization response is the request carrying the
 * identifier of an authorization request this provider parked (AuthorizationResponder): a logout that
 * sends a browser to a client is an answer that leaves too, and it carries none.
 *
 * The answer alone is a hop here. The request the browser brought is recorded where it was brought,
 * which is the authorization endpoint.
 */
final readonly class TheBrowserSentBackToTheClient implements RecordedEndpointInterface
{
    public function recognises(Request $request, Response $response, ProviderEndpoints $endpoints): bool
    {
        if (! AnswerThatLeaves::is($response, $endpoints)) {
            return false;
        }
        if (ServedAt::is($request, $endpoints->authorization)) {
            return true;
        }

        foreach ([$request->query, $request->request] as $parameters) {
            if ($parameters->get(AuthorizationResponder::INTERACTION_PARAMETER) !== null) {
                return true;
            }
        }

        return false;
    }

    public function flowOf(Request $request, ServedGrantsInterface $served): ?GrantTypeName
    {
        return OneFlowOfTheWiring::of($served->sendingTheUserToTheClient());
    }

    /**
     * The page the interaction ended on names no client: it is a page of this provider, serving whoever
     * is signed in. The hop joins the trace of the client that last brought an authorization request.
     */
    public function clientOf(Request $request): ?string
    {
        return null;
    }

    public function hops(): array
    {
        return [null, TheUserIsSentToTheClient::AUTHORIZATION_RESPONSE];
    }
}
