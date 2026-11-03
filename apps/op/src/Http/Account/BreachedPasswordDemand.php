<?php

declare(strict_types=1);

namespace App\Http\Account;

use App\Controller\AccountPasswordController;
use App\Http\InteractionPages;
use App\Http\LoginTarget;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

/**
 * What is asked of a person whose password a list of compromised passwords has found, at the next login
 * that serves no authorization request (issue #579, architecture §5.2): the browser goes to the page of
 * their password instead of the page it was going to, and that page says why.
 *
 * **It is asked inside no authorization request.** A login serving one is what a certification run plays,
 * and a page between that login and the redirection would change what the suite sees, module for module.
 * So it is asked of the two logins that serve none: the one a page of this provider asked for and the one
 * a browser makes by typing the issuer, which is that page too (LoginTarget, AccountController).
 *
 * **It is the page of the password and no page of its own**, which already says what was found and
 * already refuses what a password may not be: what is added is where the browser is sent and a sentence
 * saying so.
 *
 * **It is asked and never imposed.** A person who cannot replace their password now reaches their account
 * all the same, every page of it being where it was; what that costs is that the demand comes back at the
 * next such login, which is the point.
 *
 * **Nothing is stored for it.** What it reads is the mark the lane wrote on the credential (issue #552)
 * and the page that is still waiting for the login it diverted, so a password replaced ends the demand by
 * construction, `PasswordCredential::changePassword()` forgetting the mark, and a person who left the page
 * is asked again by the login after this one.
 */
final readonly class BreachedPasswordDemand
{
    public function __construct(
        private LoginTarget $loginTargets,
        private InteractionPages $pages,
    ) {
    }

    /**
     * The page of the password in place of the page this login was going to, and null when nothing is
     * demanded of the person who just signed in, the login then going where it was going.
     *
     * @param PasswordCredential|null $password the password this person holds, null for somebody who signs
     *                                          in by another means and holds none
     */
    public function insteadOfResuming(SessionInterface $httpSession, ?PasswordCredential $password): ?RedirectResponse
    {
        return $this->isMade($httpSession, $password)
            ? $this->pages->redirectToRoute(AccountPasswordController::ROUTE)
            : null;
    }

    /**
     * Whether the browser reading the page of the password was sent there by a login rather than having
     * gone looking for it: the password was found, and a page of this provider is still waiting for the
     * login that was diverted here.
     */
    public function isMade(SessionInterface $httpSession, ?PasswordCredential $password): bool
    {
        return $password !== null && $password->isBreached() && $this->loginTargets->isPending($httpSession);
    }

    /**
     * Where the login that was diverted was going, now that the password has been replaced, and null when
     * no page was waiting, the browser then staying on the page of the password as any other change of it
     * leaves it.
     */
    public function answered(SessionInterface $httpSession): ?RedirectResponse
    {
        $resumed = $this->loginTargets->resume($httpSession);
        if ($resumed !== null) {
            $this->loginTargets->forget($httpSession);
        }

        return $resumed;
    }
}
