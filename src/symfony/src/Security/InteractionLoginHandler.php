<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use Beffroi\Bundle\Controller\LoginController;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\LoginTarget;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * After the form login of the firewall, success or failure, the browser goes back where it came from
 * (architecture §5.2, §5.4): the login page of its interaction, or the page of the provider that asked for
 * a login and is not one (LoginTarget), the page a user approves what an appliance asked on being the one
 * (RFC 8628 §3.3). No target path is read from the body or a referer; a remembered one was written by this
 * provider into the session of that browser.
 */
final readonly class InteractionLoginHandler implements AuthenticationSuccessHandlerInterface, AuthenticationFailureHandlerInterface
{
    public function __construct(
        private InteractionPages $pages,
        private LoginTarget $loginTargets,
    ) {
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): Response
    {
        return $this->remembered($request) ?? $this->pages->redirectToPage(LoginController::ROUTE, $request);
    }

    /**
     * Kept where the security component keeps it, for the login page to read once. A refused login goes back
     * to the login page and never to the page that asked for it: that page would send the browser here again,
     * and the message would be read by nobody.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return $this->pages->redirectToPage(LoginController::ROUTE, $request);
    }

    /**
     * The page that asked for this login, when the request names no interaction: an interaction named in the
     * query of the form action is what this login was for, and a page remembered from before is what a login
     * that names none was for.
     */
    private function remembered(Request $request): ?Response
    {
        if (! $request->hasSession() || $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER) !== '') {
            return null;
        }

        return $this->loginTargets->resume($request->getSession());
    }
}
