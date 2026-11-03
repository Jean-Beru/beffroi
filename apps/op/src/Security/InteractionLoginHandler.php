<?php

declare(strict_types=1);

namespace App\Security;

use App\Controller\LoginController;
use App\Http\Account\BreachedPasswordDemand;
use App\Http\AuthorizationResponder;
use App\Http\InteractionPages;
use App\Http\LoginTarget;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * After the form login of the firewall, success or failure, the browser goes back where it came from
 * (architecture §5.2, §5.4): the login page of its interaction, or the page of the provider that asked for
 * a login and is not one (LoginTarget), the page a user approves what an appliance asked on being the one
 * (RFC 8628 §3.3). No target path is read from the body or a referer; a remembered one was written by this
 * provider into the session of that browser.
 *
 * A login that serves no authorization request is where a person whose password a list of compromised
 * passwords has found is asked to replace it (Http\Account\BreachedPasswordDemand, issue #579): the
 * browser goes to the page of their password in place of the page it was going to, which stays remembered
 * until they replace it. A login serving an authorization request is interrupted by nothing, which is what
 * a certification run plays.
 */
final readonly class InteractionLoginHandler implements AuthenticationSuccessHandlerInterface, AuthenticationFailureHandlerInterface
{
    public function __construct(
        private InteractionPages $pages,
        private LoginTarget $loginTargets,
        private BreachedPasswordDemand $demands,
    ) {
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): Response
    {
        return $this->remembered($request, $token->getUser()) ?? $this->pages->redirectToPage(LoginController::ROUTE, $request);
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
     * that names none was for. The page of the password comes first when a password of this person was
     * found in a breach: what is asked of a login is read of the credentials the provider loaded for it,
     * whichever of them signed this person in, a password somebody else holds signing them in all the same.
     */
    private function remembered(Request $request, ?UserInterface $user): ?Response
    {
        if (! $request->hasSession() || $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER) !== '') {
            return null;
        }
        $httpSession = $request->getSession();
        $password = $user instanceof SecurityUser ? $user->passwordCredential() : null;

        return $this->demands->insteadOfResuming($httpSession, $password) ?? $this->loginTargets->resume($httpSession);
    }
}
