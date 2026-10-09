<?php

declare(strict_types=1);

namespace App\Demonstration\Live\Hop;

use App\Demonstration\Live\DemonstrationClient;
use App\Demonstration\Live\DrivenCall;
use App\Demonstration\Live\DrivenHopInterface;
use App\Demonstration\Live\Holdings;
use App\Demonstration\Trace\FlowTrace;
use Beffroi\Oidc\Application\Flow\TheProviderIsAskedWhoTheUserIs;
use Beffroi\Oidc\Domain\Client\GrantTypesApart;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\ServedGrantsInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * OIDC Core §5.3.1: the client presents the access token it holds and is told who is behind it. The
 * flows that close this way are the ones that have somebody behind them, which is what the closing of
 * the picture reads too.
 */
final readonly class AskWhoTheUserIs implements DrivenHopInterface
{
    public function flows(ServedGrantsInterface $served): array
    {
        return GrantTypesApart::of($served->servedGrantTypes(), $served->actingForTheClientItself());
    }

    public function call(FlowTrace $trace, ProviderEndpoints $endpoints, DemonstrationClient $client): ?DrivenCall
    {
        $token = $trace->holds(Holdings::ACCESS_TOKEN);
        if ($token === null) {
            return null;
        }

        return new DrivenCall(Request::METHOD_GET, $endpoints->userinfo, [], $token);
    }

    public function hops(): array
    {
        return [TheProviderIsAskedWhoTheUserIs::USERINFO_REQUEST, TheProviderIsAskedWhoTheUserIs::USERINFO_RESPONSE];
    }

    public function keeps(array $answer): array
    {
        return [];
    }
}
