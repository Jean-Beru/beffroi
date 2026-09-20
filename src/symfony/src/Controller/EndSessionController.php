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
 * The end session endpoint (RP-Initiated Logout §2), GET or POST. An error is a page, never a
 * redirection (§4). The confirmation page re-submits the same parameters with the answer and the CSRF
 * token; a "no" ends nothing and sends the user nowhere.
 */
#[AsController]
final readonly class EndSessionController
{
    public const string CSRF_TOKEN_ID = 'heidi_logout';

    public const string CONFIRM_PARAMETER = 'confirm';

    public const string CONFIRM_YES = 'yes';

    /**
     * The parameters of §2 the confirmation page carries over.
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
                return $this->pages->error(Response::HTTP_FORBIDDEN, InteractionPages::INVALID_CSRF_TOKEN);
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
     * @return array<string, string> the ones that were single strings, which is what the parser accepted
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
