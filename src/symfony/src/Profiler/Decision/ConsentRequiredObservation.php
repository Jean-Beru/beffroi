<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler\Decision;

use Heidi\Bundle\Profiler\Observation;
use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;
use Heidi\Oidc\Domain\Interaction\ConsentRequired;

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
