<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use function array_keys;
use function array_map;
use Heidi\Oidc\Domain\Authorization\Prompt;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use function implode;
use function sprintf;
use const DATE_ATOM;

/**
 * The authorization request the provider parked while the user signs in and consents (architecture
 * §4.3), read whole: a page of the interaction plane carries nothing but the identifier of the
 * interaction in its URL, and everything the client asked for lives in the record behind it.
 *
 * What the request asked is shown as the parser typed it, never as the query spelled it. The
 * "id_token_hint" is a token and is said to be there without being written down; the challenge of PKCE
 * is the public half of the pair and the verifier never reaches this endpoint at all.
 */
final readonly class ProfilingInteractionRepository implements InteractionRepositoryInterface
{
    public function __construct(
        private InteractionRepositoryInterface $interactions,
        private OpProfile $profile,
    ) {
    }

    public function find(string $id): ?Interaction
    {
        $interaction = $this->interactions->find($id);
        if ($interaction !== null) {
            $this->profile->record(self::observe($interaction));
        }

        return $interaction;
    }

    public function save(Interaction $interaction): void
    {
        $this->interactions->save($interaction);
        $this->profile->record(self::observe($interaction));
    }

    private static function observe(Interaction $interaction): Observation
    {
        $request = $interaction->request;
        $challenge = $request->codeChallenge;
        $claims = $request->claims;

        return new Observation('Interaction', 'Interaction', [
            'interaction' => $interaction->id,
            'where it is' => self::stateOf($interaction),
            'created at' => $interaction->createdAt->format(DATE_ATOM),
            'expires at' => $interaction->expiresAt->format(DATE_ATOM),
            'locale' => $interaction->locale ?? 'the one of the browser',
            'client_id' => $interaction->clientId,
            'redirect_uri' => $request->redirectUri->value,
            'response mode' => $request->responseMode->value,
            'scopes requested' => implode(' ', array_map(static fn (Scope $scope): string => $scope->value, $request->scopes)),
            'PKCE' => $challenge === null ? 'none: the client is exempt (decision 0008)' : $challenge->method->value,
            'state' => $request->state === null ? 'none' : 'carried',
            'nonce' => $request->nonce === null ? 'none' : 'carried',
            'prompt' => $request->prompts === [] ? 'none' : implode(' ', array_map(static fn (Prompt $prompt): string => $prompt->value, $request->prompts)),
            'max_age' => $request->maxAge === null ? 'none' : sprintf('%d seconds', $request->maxAge),
            'acr_values' => $request->acrValues === [] ? 'none' : implode(' ', $request->acrValues),
            'ui_locales' => $request->uiLocales === [] ? 'none' : implode(' ', $request->uiLocales),
            'display' => $request->display->value ?? 'none',
            'login_hint' => $request->loginHint === null ? 'none' : 'carried',
            'id_token_hint' => $request->idTokenHint === null ? 'none' : 'carried',
            'dpop_jkt' => $request->dpopKey?->value() ?? 'none',
            'claims asked for by name' => $claims === null ? 'none' : self::claimNames($claims->idToken, $claims->userinfo),
            'session attached' => $interaction->session?->id->toRfc4122() ?? 'none yet',
            'consent attached' => $interaction->consent?->id->toRfc4122() ?? 'none yet',
        ]);
    }

    private static function stateOf(Interaction $interaction): string
    {
        if ($interaction->isCompleted()) {
            return 'completed';
        }

        return $interaction->session === null ? 'waiting for the user to authenticate' : 'authenticated, waiting for what comes next';
    }

    /**
     * OIDC Core §5.5: the names the client asked for, under the document it asked them in; what the
     * claims hold is the user, and the panel names them rather than showing them.
     *
     * @param array<string, mixed> $idToken
     * @param array<string, mixed> $userinfo
     */
    private static function claimNames(array $idToken, array $userinfo): string
    {
        $named = [];
        if ($idToken !== []) {
            $named[] = 'id_token: ' . implode(', ', array_keys($idToken));
        }
        if ($userinfo !== []) {
            $named[] = 'userinfo: ' . implode(', ', array_keys($userinfo));
        }

        return $named === [] ? 'none' : implode("\n", $named);
    }
}
