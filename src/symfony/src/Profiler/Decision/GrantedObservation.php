<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler\Decision;

use function array_keys;
use Heidi\Bundle\Profiler\Observation;
use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;
use Heidi\Oidc\Domain\Interaction\Granted;
use function implode;

/**
 * The answer that goes back to the client and the mode it goes back in; the names of the parameters and
 * never their values, a code being a credential.
 */
final readonly class GrantedObservation implements DecisionObservationInterface
{
    public function decision(): string
    {
        return 'granted';
    }

    public function observe(AuthorizationDecision $decision): Observation
    {
        return new Observation('Decision', 'Decision', [
            'outcome' => 'granted',
            'response mode' => $decision->interaction->request->responseMode,
            'parameters sent back' => $decision instanceof Granted ? implode(' ', array_keys($decision->response->parameters())) : '',
        ]);
    }
}
