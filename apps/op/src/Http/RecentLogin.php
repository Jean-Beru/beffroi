<?php

declare(strict_types=1);

namespace App\Http;

use DateInterval;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * What a page of the account asks of a session before it lets somebody change what signs them in: that
 * they proved who they are a short while ago, and not merely that a browser holds a session (architecture
 * §5.2).
 *
 * **A session is not a proof of presence.** It outlives the moment it was opened, by design: a person
 * signs in once and reads the pages of their account for the rest of the day, and so does whoever walks up
 * to a screen they left unlocked or steals the cookie of one. For the pages that only show what the
 * account holds that is the right trade; for the form that replaces the password, it is the form somebody
 * else would use to lock its owner out, so the proof is asked again.
 *
 * **It is the login of the firewall that asks**, the same one every other page of the provider uses
 * (LoginTarget): the page remembers itself, the browser goes to the login, and whatever that person holds
 * is what proves them again, a password, a passkey or a code. Nothing here asks for a kind, which would be
 * this page deciding what a credential is worth instead of the policy of the tenant.
 *
 * It bounds the GET and the POST both: a guard the form does not repeat is a guard a form post goes
 * around.
 */
final readonly class RecentLogin
{
    /**
     * Five minutes: long enough that somebody who just signed in to change their password is not asked
     * twice in a row, short enough that a session left open an hour ago proves nothing here. It is the
     * window of this one gesture and not a lifetime of the session, which the tenant decides.
     */
    public const string WITHIN = 'PT5M';

    public function __construct(
        private LoginTarget $loginTargets,
        private ClockInterface $clock,
    ) {
    }

    /**
     * Null when the session proved something inside the window, and the redirection to the login when it
     * did not: the page is remembered, so the browser comes back to it once the proof is given.
     *
     * @param string $route the page asking, a route of this provider
     * @param array<string, string> $parameters what our own code writes into it, never what a request carried
     */
    public function orSendToLogin(
        Request $request,
        AuthenticationSession $session,
        string $route,
        array $parameters = [],
    ): ?RedirectResponse {
        if ($this->isRecent($session)) {
            return null;
        }

        return $this->loginTargets->sendToLogin($request->getSession(), $route, $parameters);
    }

    /**
     * Whether the newest proof of the session is inside the window; "auth_time" is what that is (OIDC
     * Core §2), so a step-up and a re-login both count and nothing has to be told about them here.
     */
    public function isRecent(AuthenticationSession $session): bool
    {
        return $session->authenticatedAt()->add(new DateInterval(self::WITHIN)) > $this->clock->now();
    }
}
