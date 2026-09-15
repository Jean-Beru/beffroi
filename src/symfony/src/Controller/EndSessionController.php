<?php

declare(strict_types=1);

namespace Heidi\Bundle\Controller;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Bundle\Http\RequestParameters;
use Heidi\Oidc\Application\EndSession\EndSessionHandler;
use Heidi\Oidc\Application\EndSession\EndSessionRequestParser;
use Heidi\Oidc\Domain\EndSession\LoggedOut;
use Heidi\Oidc\Domain\EndSession\LogoutConfirmationRequired;
use Heidi\Oidc\Exception\OAuth2Exception;
use function is_string;
use LogicException;
use function sprintf;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

/**
 * OIDC RP-Initiated Logout 1.0 §2: the end session endpoint, GET with the parameters in the query or
 * POST with them in the form body. An error in the request is a page, never a redirection (§4). When
 * the handler must ask, the confirmation page re-submits the same parameters with the answer and the
 * CSRF token of the form; the request is parsed again, the same way, and confirm() ends the session. A
 * "no" ends nothing and sends the user nowhere: the client asked for a logout that did not happen. There
 * is no interaction to record a locale on: the pages speak the language "ui_locales" of the request
 * asks for (§2), which the confirmation form carries over, then the browser's (architecture §5.7).
 */
#[AsController]
final readonly class EndSessionController
{
    public const string CSRF_TOKEN_ID = 'heidi_logout';

    public const string INVALID_CSRF_TOKEN = 'invalid_csrf_token';

    /**
     * The name of the form field that carries the answer of the confirmation page.
     */
    public const string CONFIRM_PARAMETER = 'confirm';

    public const string CONFIRM_YES = 'yes';

    /**
     * The parameters of §2 the confirmation page carries over, as the request brought them.
     */
    public const array PARAMETERS = ['id_token_hint', 'client_id', 'post_logout_redirect_uri', 'state', 'logout_hint', 'ui_locales'];

    public function __construct(
        private TenantProvider $tenants,
        private EndSessionRequestParser $parser,
        private EndSessionHandler $handler,
        private BrowserSession $browser,
        private RequestContextFactory $contexts,
        private InteractionPages $pages,
        private CsrfTokenManagerInterface $csrf,
        private InteractionLocale $locale,
    ) {
    }

    #[Route('/logout', name: 'heidi_interaction_logout', methods: ['GET', 'POST'])]
    public function __invoke(Request $request): Response
    {
        $tenant = $this->tenants->provide();
        $parameters = RequestParameters::ofBrowserRequest($request);
        try {
            $endSessionRequest = $this->parser->parse($tenant, $parameters);
        } catch (OAuth2Exception $exception) {
            return $this->pages->error($exception->statusCode, $exception->error, $exception->errorDescription);
        }
        $this->locale->apply($request, $this->locale->choose($request, $endSessionRequest->uiLocales));
        $session = $this->browser->authenticationSession($request, $tenant);
        $context = $this->contexts->fromRequest($request);

        $answer = $request->isMethod('POST') ? ($parameters[self::CONFIRM_PARAMETER] ?? null) : null;
        if ($answer === null) {
            $decision = $this->handler->begin($endSessionRequest, $session, $context);
        } else {
            $token = $parameters['_token'] ?? null;
            if (! is_string($token) || ! $this->csrf->isTokenValid(new CsrfToken(self::CSRF_TOKEN_ID, $token))) {
                return $this->pages->error(Response::HTTP_FORBIDDEN, self::INVALID_CSRF_TOKEN);
            }
            if ($answer !== self::CONFIRM_YES) {
                return $this->pages->render('logged_out.html.twig', [
                    'logged_out' => false,
                    'client' => $endSessionRequest->client,
                ]);
            }
            $decision = $this->handler->confirm($endSessionRequest, $session, $context);
        }

        if ($decision instanceof LogoutConfirmationRequired) {
            return $this->pages->render('logout.html.twig', [
                'client' => $decision->request->client,
                'user' => $decision->session->user,
                'reason' => $decision->reason,
                'parameters' => self::carriedOver($parameters),
            ]);
        }
        if (! $decision instanceof LoggedOut) {
            throw new LogicException(sprintf('The decision "%s" is not one the end session endpoint knows.', $decision::class));
        }
        if ($decision->endedSession !== null) {
            $this->browser->unbind($request->getSession());
        }
        if ($decision->redirect !== null) {
            return $this->pages->redirect($decision->redirect->toUri());
        }

        return $this->pages->render('logged_out.html.twig', [
            'logged_out' => true,
            'client' => $decision->request->client,
        ]);
    }

    /**
     * @param array<string, mixed> $parameters
     *
     * @return array<string, string> the parameters of the request the confirmation form re-submits, the ones that were single strings, which is what the parser accepted
     */
    private static function carriedOver(array $parameters): array
    {
        $carried = [];
        foreach (self::PARAMETERS as $name) {
            $value = $parameters[$name] ?? null;
            if (is_string($value) && $value !== '') {
                $carried[$name] = $value;
            }
        }

        return $carried;
    }
}
