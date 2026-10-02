<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Profiler\Decision;

use Beffroi\Bundle\Profiler\Observation;
use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Beffroi\Oidc\Domain\Interaction\ConsentRequired;

/**
 * Why the user is asked to consent, and what the client asked for (architecture §4.3).
 */
final readonly class ConsentRequiredObservation implements DecisionObservationInterface
{
    public function decision(): string
    {
        return 'consent';
    }

    public function observe(AuthorizationDecision $decision): Observation
    {
        return new Observation('Decision', 'Decision', [
            'outcome' => 'the user is asked to consent',
            'why' => $decision instanceof ConsentRequired ? $decision->requirement->value : $decision->name(),
            'scopes asked for' => $decision instanceof ConsentRequired ? (string) $decision->scopes : '',
        ]);
    }
}
