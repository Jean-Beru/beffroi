<?php

declare(strict_types=1);

namespace App\Demonstration\Live\Hop;

use App\Demonstration\Live\DemonstrationClient;
use App\Demonstration\Live\DrivenCall;
use App\Demonstration\Live\DrivenHopInterface;
use App\Demonstration\Live\Holdings;
use App\Demonstration\Trace\FlowTrace;
use Beffroi\Oidc\Application\Flow\TheResourceServerAsksWhatTheTokenIs;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * RFC 7662 §2.1: the resource server the token was spent at hands it over and is told what it is. The
 * demonstration stands in for that resource server, which is why this hop is drawn from the fourth
 * actor of the picture and not from the client.
 */
final readonly class IntrospectTheToken implements DrivenHopInterface
{
    public function flows(ServedGrantsInterface $served): array
    {
        return $served->servedGrantTypes();
    }

    public function call(FlowTrace $trace, ProviderEndpoints $endpoints, DemonstrationClient $client): ?DrivenCall
    {
        $token = $trace->holds(Holdings::ACCESS_TOKEN);
        if ($token === null) {
            return null;
        }

        return new DrivenCall(Request::METHOD_POST, $endpoints->introspection, [
            'token' => $token,
        ]);
    }

    public function hops(): array
    {
        return [
            TheResourceServerAsksWhatTheTokenIs::INTROSPECTION_REQUEST,
            TheResourceServerAsksWhatTheTokenIs::INTROSPECTION_RESPONSE,
        ];
    }

    public function keeps(array $answer): array
    {
        return [];
    }
}
