<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Bundle\Http\InteractionPages;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * Where the browser goes after the form login of the firewall (architecture §5.2, §5.4): back to the
 * login page of the interaction it was on, in both cases. On success the page resumes the interaction
 * with the session the browser now holds and sends it on, to the consent page or to the client; on
 * failure the page shows the form again with one flat message, whatever the reason. The interaction
 * identifier travels in the query of the form action, so that no target path is read from the request
 * body or from a referer.
 */
final readonly class InteractionLoginHandler implements AuthenticationSuccessHandlerInterface, AuthenticationFailureHandlerInterface
{
    public function __construct(
        private InteractionPages $pages,
        private UrlGeneratorInterface $router,
    ) {
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): Response
    {
        return $this->pages->redirect($this->loginPage($request));
    }

    /**
     * The failure is kept where the security component keeps it, for the login page to read once.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $request->getSession()
            ->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return $this->pages->redirect($this->loginPage($request));
    }

    private function loginPage(Request $request): string
    {
        $interaction = $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER);

        return $this->router->generate('heidi_interaction_login', $interaction === '' ? [] : [
            AuthorizationResponder::INTERACTION_PARAMETER => $interaction,
        ]);
    }
}
