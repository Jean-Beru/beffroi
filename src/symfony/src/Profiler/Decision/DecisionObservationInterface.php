<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler\Decision;

use Heidi\Bundle\Profiler\Observation;
use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;

/**
 * What the panel says about one decision of the authorization endpoint. A decision the provider gains is
 * a class here and a line in the wiring; a decision nothing describes is still named, never read by its
 * class.
 */
interface DecisionObservationInterface
{
    /**
     * @return non-empty-string the decision this describes, as the decision names itself
     */
    public function decision(): string;

    public function observe(AuthorizationDecision $decision): Observation;
}
