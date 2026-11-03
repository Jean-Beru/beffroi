<?php

declare(strict_types=1);

namespace App\Profiler\Decision;

use function array_map;
use App\Profiler\Observation;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Beffroi\Oidc\Domain\Interaction\LoginRequired;
use function implode;

/**
 * Why the browser is sent to the login page (OIDC Core §3.1.2.1), the classes a step-up is still short
 * of and the kinds of credential that would reach them (decision 0010).
 */
final readonly class LoginRequiredObservation implements DecisionObservationInterface
{
    public function decision(): string
    {
        return 'login';
    }

    public function observe(AuthorizationDecision $decision): Observation
    {
        $stepUp = $decision instanceof LoginRequired ? $decision->stepUp : null;
        $why = $decision instanceof LoginRequired ? $decision->requirement->value : $decision->name();

        return new Observation('Decision', 'Decision', [
            'outcome' => 'the user authenticates',
            'why' => $why,
            'classes still short of' => $stepUp === null
                ? 'none'
                : implode(' ', array_map(static fn (AuthenticationContextClass $class): string => $class->value, $stepUp->classes)),
            'credentials that would reach one' => $stepUp === null ? 'none' : implode(' ', $stepUp->kinds()),
        ]);
    }
}
