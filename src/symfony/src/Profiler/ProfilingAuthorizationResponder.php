<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use function array_keys;
use function array_map;
use function array_slice;
use function explode;
use Heidi\Bundle\Http\AuthorizationResponderInterface;
use Heidi\Core\Domain\Session\AuthenticationContextClass;
use Heidi\Oidc\Domain\Authorization\RedirectTarget;
use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;
use Heidi\Oidc\Domain\Interaction\ConsentRequired;
use Heidi\Oidc\Domain\Interaction\Granted;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Interaction\LoginRequired;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\OAuth2Exception;
use function implode;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * What the authorization endpoint decided, which is the one thing about a request that is nowhere in it:
 * the page the browser is sent to and why (OIDC Core §3.1.2.1), the classes a step-up is still short of
 * and the kinds of credential that would reach them (decision 0010), or the answer that goes back to the
 * client and the mode it goes back in.
 *
 * A refusal is said with the error of RFC 6749 §5.2 and its description, which is the sentence the
 * provider wrote and never anything the request chose.
 */
final readonly class ProfilingAuthorizationResponder implements AuthorizationResponderInterface
{
    public function __construct(
        private AuthorizationResponderInterface $responder,
        private OpProfile $profile,
    ) {
    }

    public function respond(Request $request, AuthorizationDecision $decision): Response
    {
        $this->profile->record(self::observe($decision));

        return $this->responder->respond($request, $decision);
    }

    public function failure(Request $request, RedirectTarget $target, OAuth2Exception $exception, ?Interaction $interaction = null): Response
    {
        $this->profile->record(new Observation('Decision', 'Decision', [
            'outcome' => $exception->redirectable ? 'refused, and the client is told' : 'refused, and the user is shown a page',
            'error' => $exception->error,
            'description' => $exception->errorDescription,
            'response mode' => $target->responseMode->value,
        ]));

        return $this->responder->failure($request, $target, $exception, $interaction);
    }

    public function unresumable(Request $request, Interaction $interaction, InteractionExpiredException|InteractionCompletedException $exception): Response
    {
        $this->profile->record(new Observation('Decision', 'Decision', [
            'outcome' => 'the interaction cannot be resumed',
            'interaction' => $interaction->id,
        ]));

        return $this->responder->unresumable($request, $interaction, $exception);
    }

    public function unknownInteraction(): Response
    {
        $this->profile->record(new Observation('Decision', 'Decision', [
            'outcome' => 'a page was reached without an interaction this browser began',
        ]));

        return $this->responder->unknownInteraction();
    }

    private static function observe(AuthorizationDecision $decision): Observation
    {
        if ($decision instanceof LoginRequired) {
            $stepUp = $decision->stepUp;

            return new Observation('Decision', 'Decision', [
                'outcome' => 'the user authenticates',
                'why' => $decision->requirement->value,
                'classes still short of' => $stepUp === null
                    ? 'none'
                    : implode(
                        ' ',
                        array_map(static fn (AuthenticationContextClass $class): string => $class->value, $stepUp->classes),
                    ),
                'credentials that would reach one' => $stepUp === null ? 'none' : implode(' ', $stepUp->kinds()),
            ]);
        }
        if ($decision instanceof ConsentRequired) {
            return new Observation('Decision', 'Decision', [
                'outcome' => 'the user is asked to consent',
                'why' => $decision->requirement->value,
                'scopes asked for' => implode(' ', array_map(static fn (Scope $scope): string => $scope->value, $decision->scopes)),
            ]);
        }
        if ($decision instanceof Granted) {
            return new Observation('Decision', 'Decision', [
                'outcome' => 'granted',
                'response mode' => $decision->interaction->request->responseMode->value,
                'parameters sent back' => implode(' ', array_keys($decision->response->parameters())),
            ]);
        }

        $parts = explode('\\', $decision::class);

        return new Observation('Decision', 'Decision', [
            'outcome' => implode('', array_slice($parts, -1)),
        ]);
    }
}
