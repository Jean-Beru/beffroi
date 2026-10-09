<?php

declare(strict_types=1);

namespace App\Demonstration\Live;

use App\Demonstration\ProviderEndpointsOfTheTenant;
use App\Demonstration\Trace\FlowTrace;
use App\Demonstration\Trace\TracedHop;
use App\Demonstration\Trace\TraceStore;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Port\FlowPicturesInterface;

/**
 * What drives a flow of this provider from a page of the demonstration (issue #462): the run is opened,
 * and every advance takes the next hop the demonstration takes itself, for real, against the endpoints
 * this provider announces.
 *
 * The hops it does not take are the ones a browser takes: a device code typed on another screen, a
 * backchannel request allowed on a telephone. Those reach this provider from a real browser and the
 * recorder of the provider's side writes them into the same trace, which is why a run is followed hop
 * by hop without the demonstration ever standing in for the user.
 *
 * A flow whose opening no browser of the demonstration can take, or that the lab registered no client
 * for, is not driven at all, and the page says so: a flow drawn is not always a flow that can be
 * played from a page.
 */
final readonly class FlowDriver
{
    public function __construct(
        private NextHop $next,
        private TakenHop $taken,
        private FlowPicturesInterface $pictures,
        private DemonstrationClients $clients,
        private ProviderEndpointsOfTheTenant $provider,
        private TraceStore $traces,
    ) {
    }

    public function drives(GrantTypeName $flow): bool
    {
        $picture = $this->pictures->of($flow);

        return $picture !== null && $this->clients->of($flow) !== null && $this->next->opens($picture);
    }

    /**
     * A run of that flow, started over: what the client of the previous run held is forgotten with it.
     */
    public function open(GrantTypeName $flow): ?FlowTrace
    {
        $client = $this->clients->of($flow);

        return $client === null ? null : $this->traces->opened($flow->value, $client->id);
    }

    /**
     * The next hop taken, and the trace as it is once it has been. A run with nothing left to take
     * gives the trace back untouched, which the page reads as a flow played to its end.
     */
    public function advance(GrantTypeName $flow): ?FlowTrace
    {
        $picture = $this->pictures->of($flow);
        $client = $this->clients->of($flow);
        if ($picture === null || $client === null) {
            return null;
        }
        $trace = $this->trace($flow) ?? $this->traces->opened($flow->value, $client->id);
        $driven = $this->next->of($picture, $trace);
        if ($driven === null) {
            return $trace;
        }
        $call = $driven->call($trace, $this->provider->endpoints(), $client);
        if ($call === null) {
            return $this->traces->save($trace->with(TracedHop::unreachable(
                $driven->hops()[1],
                $trace->startedAt,
                'The client of this run does not hold what this hop needs: the flow did not get that far.',
            )));
        }

        return $this->traces->save($this->taken->take($driven, $call, $trace, $client));
    }

    public function trace(GrantTypeName $flow): ?FlowTrace
    {
        $client = $this->clients->of($flow);

        return $client === null ? null : $this->traces->of($flow->value, $client->id);
    }
}
