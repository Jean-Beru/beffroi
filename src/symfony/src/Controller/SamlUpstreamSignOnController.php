<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Controller;

use Beffroi\Bundle\Doctrine\TenantProvider;
use Beffroi\Bundle\Http\AuthorizationResponder;
use Beffroi\Bundle\Http\AuthorizationResponderInterface;
use Beffroi\Bundle\Http\BrowserSession;
use Beffroi\Bundle\Http\InteractionPages;
use Beffroi\Bundle\Http\LoginTarget;
use Beffroi\Bundle\Saml\SamlPostPage;
use Beffroi\Bundle\Saml\ServiceProviderRoutes;
use Beffroi\Bundle\Saml\UpstreamSignOns;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Oidc\Domain\Authorization\Prompt;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Exception\InteractionCompletedException;
use Beffroi\Oidc\Exception\InteractionExpiredException;
use Beffroi\Saml\Application\Upstream\UpstreamSignOn;
use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * Where an interaction of the browser starts a sign-on at an upstream identity provider of the SAML service provider of
 * the tenant (beffroi/saml, spec/saml.md S-51, section 6.11): an interaction this browser began and can still resume,
 * or none, for the login a page of the provider waits for (LoginTarget, S-61), and the entity ID of a provider the
 * tenant declares, nothing else; the request forces a login when the authorization request of the interaction asks for
 * a fresh one, or when a page asks it of a browser signed in already (S-49), is remembered in the HTTP session of the
 * browser under its RelayState with the interaction or the page it serves (S-50), and is carried to the provider by a
 * redirection over HTTP-Redirect or by the page that posts it over HTTP-POST. Which provider an address goes to is the discovery of the login page (issue #785), which sends the
 * browser here.
 *
 * A deployment that does not enable "beffroi.saml.service_provider" wires no sign-on and answers 404, as the metadata
 * of the role does (S-41); so does a tenant that holds no SAML key.
 */
#[AsController]
final readonly class SamlUpstreamSignOnController
{
    /**
     * The code of the page a sign-on that cannot start is shown, which the template of the error explains.
     */
    public const string REFUSED = 'saml_upstream_sign_on_refused';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private AuthorizationResponderInterface $responder,
        private UpstreamSignOns $signOns,
        private SamlPostPage $page,
        private InteractionPages $pages,
        private ClockInterface $clock,
        private LoginTarget $loginTargets,
        private ?UpstreamSignOn $signOn = null,
    ) {
    }

    #[Route(ServiceProviderRoutes::UPSTREAM_SIGN_ON_PATH, name: ServiceProviderRoutes::UPSTREAM_SIGN_ON, methods: ['GET'])]
    public function __invoke(Request $request): Response
    {
        if (! $this->signOn instanceof UpstreamSignOn) {
            throw new NotFoundHttpException('This tenant serves no SAML service provider.');
        }
        $tenant = $this->tenants->provide();
        $session = $this->browser->authenticationSession($request, $tenant);
        $now = $this->clock->now();
        $id = $request->query->getString(AuthorizationResponder::INTERACTION_PARAMETER);
        if ($id === '') {
            // the login a page of the provider waits for (LoginTarget, S-61): it comes back to that page, and a
            // person signed in already is asked for a fresh proof, which is all such a page asks of one (S-49)
            $for = $this->loginTargets->waiting($request->getSession());
            if ($for === null) {
                return $this->responder->unknownInteraction();
            }
            $forceAuthn = $session instanceof AuthenticationSession;
        } else {
            $for = $this->browser->pending($request, $tenant, $id);
            if ($for === null) {
                return $this->responder->unknownInteraction();
            }
            try {
                $for->assertResumable($now);
            } catch (InteractionExpiredException|InteractionCompletedException $exception) {
                return $this->responder->unresumable($request, $for, $exception);
            }
            $forceAuthn = self::forceAuthn($for, $session, $now);
        }
        try {
            $sent = $this->signOn->start($tenant, $request->query->getString(ServiceProviderRoutes::IDENTITY_PROVIDER_PARAMETER), $forceAuthn);
        } catch (UpstreamSignOnRefusedException $exception) {
            return $this->pages->error(Response::HTTP_BAD_REQUEST, self::REFUSED, $exception->getMessage());
        } catch (KeyNotFoundException $exception) {
            throw new NotFoundHttpException('This tenant serves no SAML service provider.', $exception);
        }
        $this->signOns->keep($request->getSession(), $tenant, $for, $sent);
        if ($sent->message instanceof RedirectedMessage) {
            return new RedirectResponse($sent->message->url, Response::HTTP_FOUND, [
                ...InteractionPages::HEADERS,
                'Cache-Control' => 'no-cache, no-store',
                'Pragma' => 'no-cache',
            ]);
        }

        return $this->page->signOnRequest($sent->message);
    }

    /**
     * S-49: a fresh login when the authorization request asks for one, prompt=login, or a max_age the session the
     * browser holds exceeds (OIDC Core §3.1.2.1); a browser that holds none exceeds no max_age.
     */
    private static function forceAuthn(Interaction $interaction, ?AuthenticationSession $session, DateTimeImmutable $now): bool
    {
        $authorization = $interaction->request;

        return $authorization->hasPrompt(Prompt::Login) || $session instanceof AuthenticationSession && $authorization->maxAgeExceededBy($session, $now);
    }
}
