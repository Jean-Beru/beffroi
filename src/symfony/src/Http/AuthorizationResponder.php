<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use Heidi\Oidc\Domain\Authorization\AuthorizationErrorResponse;
use Heidi\Oidc\Domain\Authorization\RedirectTarget;
use Heidi\Oidc\Domain\Interaction\AuthorizationDecision;
use Heidi\Oidc\Domain\Interaction\ConsentRequired;
use Heidi\Oidc\Domain\Interaction\Granted;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Interaction\LoginRequired;
use Heidi\Oidc\Exception\InteractionCompletedException;
use Heidi\Oidc\Exception\InteractionExpiredException;
use Heidi\Oidc\Exception\OAuth2Exception;
use LogicException;
use function sprintf;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Turns what the AuthorizationHandler decided into where the browser goes (architecture §4.3, §5.2):
 * the login page, the consent page, or back to the client with the code; and turns what it refused into
 * a redirection with the error when the client may hear it (RFC 6749 §4.1.2.1) or a page when it may not.
 * The browser is told which interactions it began and which are over, so that only it can resume them.
 */
final readonly class AuthorizationResponder
{
    public const string INTERACTION_EXPIRED = 'interaction_expired';

    public const string INTERACTION_COMPLETED = 'interaction_completed';

    public const string UNKNOWN_INTERACTION = 'unknown_interaction';

    /**
     * The name of the query parameter that carries the interaction identifier to the login and consent
     * pages.
     */
    public const string INTERACTION_PARAMETER = 'interaction';

    public function __construct(
        private InteractionPages $pages,
        private BrowserSession $browser,
        private UrlGeneratorInterface $router,
    ) {
    }

    public function respond(Request $request, AuthorizationDecision $decision): Response
    {
        if ($decision instanceof LoginRequired) {
            return $this->toPage($request, $decision->interaction, 'heidi_interaction_login');
        }
        if ($decision instanceof ConsentRequired) {
            return $this->toPage($request, $decision->interaction, 'heidi_interaction_consent');
        }
        if ($decision instanceof Granted) {
            $this->browser->forget($request->getSession(), $decision->interaction);

            return $this->pages->redirect($decision->response->toUri());
        }

        throw new LogicException(sprintf('The decision "%s" is not one the authorization endpoint knows.', $decision::class));
    }

    /**
     * An error the handler or the second stage of the parser raised: sent back to the redirect URI with
     * "state" and "iss" when the error may be, shown to the user otherwise. Either way the interaction,
     * when there was one, is over for this browser.
     */
    public function failure(Request $request, RedirectTarget $target, OAuth2Exception $exception, ?Interaction $interaction = null): Response
    {
        if ($interaction !== null) {
            $this->browser->forget($request->getSession(), $interaction);
        }
        if ($exception->redirectable) {
            return $this->pages->redirect(AuthorizationErrorResponse::fromException($target, $exception)->toUri());
        }

        return $this->pages->error($exception->statusCode, $exception->error, $exception->errorDescription);
    }

    /**
     * An interaction that took too long or already had its outcome: shown to the user, who starts again
     * from the client; nothing is sent to the redirect URI on the client's behalf.
     */
    public function unresumable(Request $request, Interaction $interaction, InteractionExpiredException|InteractionCompletedException $exception): Response
    {
        $this->browser->forget($request->getSession(), $interaction);
        if ($exception instanceof InteractionExpiredException) {
            return $this->pages->error(Response::HTTP_BAD_REQUEST, self::INTERACTION_EXPIRED, 'The request took too long. Start again from the application.');
        }

        return $this->pages->error(Response::HTTP_BAD_REQUEST, self::INTERACTION_COMPLETED, 'The request was already answered. Start again from the application.');
    }

    /**
     * A page reached without an interaction this browser began.
     */
    public function unknownInteraction(): Response
    {
        return $this->pages->error(Response::HTTP_BAD_REQUEST, self::UNKNOWN_INTERACTION, 'No request is waiting for this page. Start again from the application.');
    }

    private function toPage(Request $request, Interaction $interaction, string $route): Response
    {
        $this->browser->begin($request->getSession(), $interaction);

        return $this->pages->redirect($this->router->generate($route, [
            self::INTERACTION_PARAMETER => $interaction->id,
        ]));
    }
}
