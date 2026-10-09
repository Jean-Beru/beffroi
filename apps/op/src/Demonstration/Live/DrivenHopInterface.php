<?php

declare(strict_types=1);

namespace App\Demonstration\Live;

use App\Demonstration\Trace\FlowTrace;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Discovery\ProviderEndpoints;
use Beffroi\Oidc\Port\ServedGrantsInterface;

/**
 * One hop the demonstration takes itself (issue #462): the call it makes, the hops of the picture that
 * call fills, and what the client of the run keeps from the answer.
 *
 * The hops a demonstration does not take are the ones a browser takes, a device code typed somewhere
 * else, a backchannel request answered on a telephone: those reach this provider from a real browser
 * and are recorded as they do. A hop no driven hop claims is a hop the page waits for.
 *
 * A hop the demonstration gains is a class added to the wiring.
 */
interface DrivenHopInterface
{
    /**
     * @throws \Beffroi\Oidc\Exception\InvalidArgumentException when the wiring does not hold together
     *
     * @return list<GrantTypeName> the flows of the wiring it takes its hop for
     */
    public function flows(ServedGrantsInterface $served): array;

    /**
     * The call to make, or null when the client of the run does not hold what the hop needs: a token to
     * introspect, a code to poll on. A hop that cannot be taken is said to be, and nothing is sent.
     */
    public function call(FlowTrace $trace, ProviderEndpoints $endpoints, DemonstrationClient $client): ?DrivenCall;

    /**
     * The hop its call fills and the hop the answer fills.
     *
     * @return array{string, string}
     */
    public function hops(): array;

    /**
     * What the client of the run holds once it has been answered: the code it polls on, the token it
     * will present. Nothing of it is ever drawn.
     *
     * @param array<array-key, mixed> $answer
     *
     * @return array<string, string>
     */
    public function keeps(array $answer): array;
}
