<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Saml;

use Beffroi\Bundle\EndSession\FrontChannelLogoutRenderer;
use Beffroi\Bundle\Http\FormTarget;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Key\KmsUnavailableListener;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Saml\Application\SingleLogout\ProviderLogout;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainEnded;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainStarted;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;
use Beffroi\Saml\Exception\LogoutRefusedException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Throwable;

/**
 * What the browser is given once it has ended the sessions it held (beffroi/saml, spec/saml.md S-29 to S-36): the page
 * of Front-Channel Logout 1.0 for the clients of OpenID Connect of those sessions first, which resumes the chain of
 * SAML logout at the route of the provider, then each service provider of the sessions told in turn, then where the
 * logout ends. beffroi/saml knows no client of OpenID Connect and beffroi/oidc no service provider (spec/saml.md
 * section 2): the two meet here, in the bundle, where the end session endpoint, the page of the account and the single
 * logout service ask for them.
 */
final readonly class LogoutChainPages
{
    public function __construct(
        private ProviderLogout $logout,
        private FrontChannelLogoutRenderer $frontChannel,
        private InteractionPages $pages,
        private SamlPostPage $postPage,
        private UrlGeneratorInterface $urls,
        private FormTarget $formTargets,
    ) {
    }

    /**
     * After the browser ended $sessions, at the end session endpoint or on the page of the account (S-29): the chain
     * begun, the page of S-35 first. Null when there is nothing to tell and no page to show, the caller then answering
     * as it did before the chain existed.
     *
     * @param list<AuthenticationSession> $sessions
     * @param string|null $continueTo where the logout ends, null for the page that says the browser is signed out
     *
     * @throws LogoutRefusedException when another request took the chain first
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws RuntimeException when the salt of the tenant can neither be read nor drawn
     */
    public function begin(Tenant $tenant, array $sessions, ?string $continueTo): ?Response
    {
        $begun = $this->logout->begin($tenant, $sessions, null, $continueTo);
        if ($begun instanceof LogoutChainStarted) {
            return $this->started($tenant, $begun);
        }

        return $this->frontChannel->render($sessions, $begun->continueTo);
    }

    /**
     * A chain written (S-35): the page of Front-Channel Logout 1.0 for its sessions, which resumes it at the route of
     * the provider, or, when no client of them is loaded by such a page, the chain resumed at once. A first step that
     * meets a KMS that does not answer has written the chain back (S-32): the browser is sent to that route with its
     * reference, where a request played again plays the step again, and where the outage is a 503.
     *
     * @throws LogoutRefusedException when another request took the chain first
     * @throws KeyNotFoundException
     * @throws RuntimeException
     */
    public function started(Tenant $tenant, LogoutChainStarted $started): Response
    {
        $continue = $this->urls->generate(
            IdentityProviderRoutes::SINGLE_LOGOUT_CONTINUE,
            [
                IdentityProviderRoutes::CHAIN_PARAMETER => $started->reference,
            ],
            UrlGeneratorInterface::ABSOLUTE_URL,
        );
        $page = $this->frontChannel->render($started->sessions, $continue);
        if ($page !== null) {
            return $page;
        }
        try {
            return $this->step($this->logout->resume($tenant, $started->reference));
        } catch (Throwable $failure) {
            if (KmsUnavailableListener::outageBehind($failure) === null) {
                throw $failure;
            }

            return $this->pages->redirect($continue);
        }
    }

    /**
     * A step of the chain as the browser is given it: a message to a service provider over HTTP-Redirect, a 302 with
     * the caching headers of the binding (SAML Bindings §3.4.5.1); over HTTP-POST, the page that posts it; the end, a
     * redirection to where the starter named, or the page that says the browser is signed out (S-34).
     */
    public function step(PostedForm|RedirectedMessage|LogoutChainEnded $step): Response
    {
        if ($step instanceof RedirectedMessage) {
            return new RedirectResponse($step->url, Response::HTTP_FOUND, [
                ...InteractionPages::HEADERS,
                'Cache-Control' => 'no-cache, no-store',
                'Pragma' => 'no-cache',
            ]);
        }
        if ($step instanceof PostedForm) {
            return $this->postPage->render($step);
        }
        if ($step->continueTo !== null) {
            return $this->pages->redirect($step->continueTo);
        }

        return $this->pages->render('logged_out.html.twig', [
            'logged_out' => true,
        ]);
    }

    /**
     * S-36: a page whose form may end $session names, in its "form-action", the origin of each single logout service
     * the chain of that session would go to, a browser checking the directive over every redirection of the submission.
     */
    public function mayEnd(Request $request, AuthenticationSession $session): void
    {
        foreach ($this->logout->destinations($session) as $destination) {
            $this->formTargets->mayReach($request, SamlPostPage::originOf($destination));
        }
    }
}
