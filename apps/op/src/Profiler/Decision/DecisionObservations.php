<?php

declare(strict_types=1);

namespace App\Profiler\Decision;

use App\Profiler\Observation;
use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;

/**
 * What the panel knows how to say about a decision, in the order it is wired. A decision nothing
 * describes is shown by its name rather than left out, so that the panel of a provider that decided
 * something new still says what it decided.
 */
final readonly class DecisionObservations
{
    /**
     * @var array<string, DecisionObservationInterface>
     */
    private array $observations;

    /**
     * @param iterable<DecisionObservationInterface> $observations
     */
    public function __construct(iterable $observations)
    {
        $wired = [];
        foreach ($observations as $observation) {
            $wired[$observation->decision()] = $observation;
        }
        $this->observations = $wired;
    }

    public function of(AuthorizationDecision $decision): Observation
    {
        $observation = $this->observations[$decision->name()] ?? null;

        return $observation?->observe($decision) ?? new Observation('Decision', 'Decision', [
            'outcome' => $decision->name(),
        ]);
    }
}
