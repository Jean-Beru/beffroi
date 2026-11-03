<?php

declare(strict_types=1);

namespace App\Http;

use App\Http\Decision\DecisionRenderers;
use App\Http\ResponseMode\AuthorizationResponseRenderers;
use Beffroi\Oidc\Domain\Authorization\AuthorizationAnswer;
use Beffroi\Oidc\Domain\Authorization\AuthorizationErrorResponse;
use Beffroi\Oidc\Domain\Authorization\RedirectTarget;
use Beffroi\Oidc\Domain\Interaction\AuthorizationDecision;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Oidc\Exception\OAuth2Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Turns a decision of the AuthorizationHandler into where the browser goes (architecture §4.3, §5.2),
 * and a refusal into an answer to the client when it may hear it (RFC 6749 §4.1.2.1) or a page
 * otherwise. How the answer reaches the client is the response mode of the request, a refusal as well as
 * a code (OIDC Core §3.1.2.6); the renderer of that mode shapes it, this class never does.
 */
final readonly class AuthorizationResponder implements AuthorizationResponderInterface
{
    public const string INTERACTION_EXPIRED = 'interaction_expired';

    public const string INTERACTION_COMPLETED = 'interaction_completed';

    public const string UNKNOWN_INTERACTION = 'unknown_interaction';

    /**
     * The query parameter that carries the interaction identifier to the pages.
     */
    public const string INTERACTION_PARAMETER = 'interaction';

    public function __construct(
        private InteractionPages $pages,
        private BrowserSession $browser,
        private AuthorizationResponseRenderers $renderers,
        private DecisionRenderers $decisions,
    ) {
    }

    public function respond(Request $request, AuthorizationDecision $decision): Response
    {
        return $this->decisions->render($request, $decision);
    }

    /**
     * Sent back to the redirect URI when the error may be, shown to the user otherwise; the interaction is over either way.
     */
    public function failure(Request $request, RedirectTarget $target, OAuth2Exception $exception, ?Interaction $interaction = null): Response
    {
        if ($interaction !== null) {
            $this->browser->forget($request->getSession(), $interaction);
        }
        if ($exception->redirectable) {
            $error = AuthorizationErrorResponse::fromException($target, $exception);

            return $this->renderers->render($target->responseMode, new AuthorizationAnswer($target->client, $error->redirectUri, $error->parameters()));
        }

        return $this->pages->error($exception->statusCode, $exception->error, $exception->errorDescription);
    }

    /**
     * Shown to the user; nothing is sent to the redirect URI on the client's behalf.
     */
    public function unresumable(Request $request, Interaction $interaction, InteractionExpiredException|InteractionCompletedException $exception): Response
    {
        $this->browser->forget($request->getSession(), $interaction);
        if ($exception instanceof InteractionExpiredException) {
            return $this->pages->error(Response::HTTP_BAD_REQUEST, self::INTERACTION_EXPIRED);
        }

        return $this->pages->error(Response::HTTP_BAD_REQUEST, self::INTERACTION_COMPLETED);
    }

    /**
     * A page reached without an interaction this browser began.
     */
    public function unknownInteraction(): Response
    {
        return $this->pages->error(Response::HTTP_BAD_REQUEST, self::UNKNOWN_INTERACTION);
    }
}
