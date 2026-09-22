<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Bundle\Http\InteractionPages;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * After the form login of the firewall, success or failure, the browser goes back to the login page of
 * its interaction (architecture §5.2, §5.4); no target path is read from the body or a referer.
 */
final readonly class InteractionLoginHandler implements AuthenticationSuccessHandlerInterface, AuthenticationFailureHandlerInterface
{
    public function __construct(
        private InteractionPages $pages,
    ) {
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token): Response
    {
        return $this->pages->redirectToPage('heidi_interaction_login', $request);
    }

    /**
     * Kept where the security component keeps it, for the login page to read once.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return $this->pages->redirectToPage('heidi_interaction_login', $request);
    }
}
