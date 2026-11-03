<?php

declare(strict_types=1);

namespace App\Http\Account;

/**
 * A page of the account a session is not enough to reach (architecture §5.2): whoever holds the session
 * proved who they are inside the window of RecentLogin, or the browser goes to the login of the firewall
 * and comes back here once it has a fresh proof.
 *
 * **What asks is what adds or takes away a way in**: the form that replaces the password, the pages that
 * enrol a passkey or an authenticator app, the buttons that revoke one, the renewal that invalidates the
 * backup codes somebody wrote down. A session outlives the moment it was opened, by design, and so does
 * whoever walks up to a screen left unlocked or takes the cookie of one; for a page that shows what the
 * account holds that is the right trade, and for these it is the way somebody else locks a person out.
 *
 * **It is said on the page and called nowhere** (RecentProofListener): the rule is asked of the GET and of
 * the POST by construction, because a guard a form does not repeat is a guard a form post goes around.
 * Every page of the account says which of the two it is, this one or ReachedOnTheSessionAloneInterface,
 * and a page that says neither fails a test: what asks is read off the pages and is no list to remember.
 */
interface AsksForARecentProofInterface
{
    /**
     * The page of the account the browser comes back to once the proof is given, a route of this provider:
     * this page when it is the page being read, and the page that holds the form when it is the form being
     * posted.
     */
    public function comesBackTo(): string;
}
