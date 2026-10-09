<?php

declare(strict_types=1);

namespace App\Demonstration\Trace\Endpoint;

use App\Demonstration\Trace\RecordedEndpointInterface;
use Beffroi\Oidc\Application\Flow\TheUserIsAskedOnAnotherDevice;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Where the user of a device flow answers (RFC 8628 §3.3): the page the code is typed at. The hop is
 * the answer and not the page, so it is the form coming back that is drawn, and what the browser
 * carried with it is what the drawing shows.
 *
 * The browser names no client: it holds a code and nothing else, which is the whole point of this
 * flow. The hop joins the trace of the client that last played it.
 */
final readonly class TheDeviceVerificationPage implements RecordedEndpointInterface
{
    public function recognises(Request $request, Response $response, ProviderEndpoints $endpoints): bool
    {
        return ServedAt::is($request, $endpoints->deviceVerification) && $request->isMethod(Request::METHOD_POST);
    }

    public function flowOf(Request $request, ServedGrantsInterface $served): ?GrantTypeName
    {
        return OneFlowOfTheWiring::of($served->askingTheUserOnAnotherDevice());
    }

    public function clientOf(Request $request): ?string
    {
        return null;
    }

    public function hops(): array
    {
        return [TheUserIsAskedOnAnotherDevice::USER_CODE, null];
    }
}
