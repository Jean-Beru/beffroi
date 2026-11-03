<?php

declare(strict_types=1);

namespace App\Http;

use App\Doctrine\TenantProvider;
use App\Plane\Plane;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * What every page of the account asks before anything else (architecture §5.2): the session of the core
 * this browser holds, and the form token when the page posts. A browser without a session is told to
 * sign in first, and there is nowhere to send it: a page of the account belongs to no client and to no
 * interaction. The one place the two refusals are written, so that a page added to the account repeats
 * neither.
 */
final readonly class AccountAccess
{
    /**
     * How a page of the account is known: its route says so, the way the name of a route says its plane
     * (Plane). What walks the pages of the account reads this and holds no list of them, so a page added to
     * the account is walked by being routed.
     */
    public const string ROUTE_PREFIX = Plane::INTERACTION_ROUTE_PREFIX . 'account';

    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private FormToken $formTokens,
        private InteractionPages $pages,
    ) {
    }

    /**
     * The session of the signed-in user, or the page that refuses: unauthorized without a session,
     * forbidden when the form token of the named identifier does not hold. A page that posts nothing
     * names no identifier and is not asked for a token.
     */
    public function granted(Request $request, ?string $csrfTokenId = null): AuthenticationSession|Response
    {
        $session = $this->signedIn($request);
        if ($session === null) {
            return $this->pages->error(Response::HTTP_UNAUTHORIZED, InteractionPages::LOGIN_REQUIRED);
        }
        $refusal = $csrfTokenId === null
            ? null
            : $this->formTokens->refusal($request->request->getString(FormToken::PARAMETER), $csrfTokenId);
        if ($refusal !== null) {
            return $refusal;
        }

        return $session;
    }

    /**
     * The session alone, for the caller that refuses in a shape of its own: the options of a ceremony
     * are asked for by a script and answered in JSON.
     */
    public function signedIn(Request $request): ?AuthenticationSession
    {
        return $this->browser->authenticationSession($request, $this->tenants->provide());
    }
}
