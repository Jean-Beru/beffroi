<?php

declare(strict_types=1);

namespace App\Demonstration\Live\Hop;

use App\Demonstration\Live\DemonstrationClient;
use App\Demonstration\Live\DrivenCall;
use App\Demonstration\Live\DrivenHopInterface;
use App\Demonstration\Live\Holdings;
use App\Demonstration\Trace\FlowTrace;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Domain\Flow\TokenEndpointHops;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * CIBA Core §10.1: the client asks the token endpoint for the request it is waiting on, and is told to
 * wait until the user this provider reached has answered. The hop repeats, as the polled hop of the
 * device flow does.
 */
final readonly class PollForTheTokensOfABackchannelFlow implements DrivenHopInterface
{
    public function flows(ServedGrantsInterface $served): array
    {
        return $served->askingTheUserThroughABackchannel();
    }

    public function call(FlowTrace $trace, ProviderEndpoints $endpoints, DemonstrationClient $client): ?DrivenCall
    {
        $requestId = $trace->holds(Holdings::AUTH_REQUEST_ID);
        if ($requestId === null) {
            return null;
        }

        return new DrivenCall(Request::METHOD_POST, $endpoints->token, [
            'grant_type' => $trace->grantType,
            Holdings::AUTH_REQUEST_ID => $requestId,
        ]);
    }

    public function hops(): array
    {
        return [TokenEndpointHops::REQUEST, TokenEndpointHops::RESPONSE];
    }

    public function keeps(array $answer): array
    {
        return Holdings::kept($answer, [Holdings::ACCESS_TOKEN, Holdings::REFRESH_TOKEN]);
    }
}
