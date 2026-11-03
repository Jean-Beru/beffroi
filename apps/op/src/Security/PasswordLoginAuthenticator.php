<?php

declare(strict_types=1);

namespace App\Security;

use App\Controller\LoginController;
use App\Doctrine\TenantProvider;
use App\Http\InteractionPages;
use App\Http\RequestContextFactory;
use Beffroi\Core\Application\Authentication\AuthenticationFailedException;
use Beffroi\Core\Application\Authentication\PasswordVerification;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use function trim;

/**
 * The form login on the firewall of the interaction pages (architecture §5.4), in the place of Symfony's
 * own: the username and the password the login page posts, handed to the core, which names the user,
 * counts the attempt, pays the decoy, verifies the hash, refuses a disabled account after the password,
 * dates and rehashes the credential and announces every outcome (PasswordVerification). The order of a
 * login is written there and nowhere else (issue #130): the firewall keeps the form token, the token of
 * the firewall and the redirection, which is what Symfony asks of an authenticator, and no second copy of
 * what a login does.
 *
 * **The form token is checked before the password reaches the core**, because a form without its token is
 * not an attempt on an account: it must cost the person it names no attempt, no decoy and no act in their
 * journal. It is checked here and not by the badge of the component, whose listener runs once the passport
 * exists, which is after the core has answered: one check, in the one place the order allows.
 *
 * **A field left empty is refused here** and never counted: an empty password is not a guess at one, and
 * that is what Symfony's form login does with it.
 *
 * The passport carries the password (VerifiedPassword) for the one reader of it after a login, the lookup
 * of compromised passwords, and the user the core loaded rather than one loaded again. A refusal is the
 * flat exception of the component, the reason it carries being the core's, already announced: the login
 * page shows one message whatever happened (decision 0006) and the failure listener has nothing to add on
 * this route.
 */
final readonly class PasswordLoginAuthenticator implements AuthenticatorInterface, InteractiveAuthenticatorInterface, AuthenticationEntryPointInterface
{
    /**
     * The identifier of the token the three logins post, the form of the login page, the passkey it offers and the
     * code of the code page (PasskeyLoginAuthenticator, TotpLoginAuthenticator). The provider's own, like the token of
     * every other form of the provider that carries one, so that no list of stateless identifiers an application
     * declares for the forms of Symfony reaches these pages (issue #891).
     */
    public const string CSRF_TOKEN_ID = 'beffroi_login';

    public const string CSRF_TOKEN_PARAMETER = '_csrf_token';

    public const string USERNAME_PARAMETER = '_username';

    public const string PASSWORD_PARAMETER = '_password';

    public function __construct(
        private TenantProvider $tenants,
        private PasswordVerification $verification,
        private CsrfTokenManagerInterface $csrfTokens,
        private RequestContextFactory $contexts,
        private InteractionLoginHandler $handler,
        private InteractionPages $pages,
    ) {
    }

    public function supports(Request $request): bool
    {
        return $request->isMethod('POST') && $request->attributes->getString('_route') === LoginController::ROUTE;
    }

    public function authenticate(Request $request): Passport
    {
        $username = trim($request->request->getString(self::USERNAME_PARAMETER));
        $password = $request->request->getString(self::PASSWORD_PARAMETER);
        if ($request->hasSession()) {
            // what the login page shows in the field when it comes back refused, where the component
            // keeps it (AuthenticationUtils::getLastUsername)
            $request->getSession()->set(SecurityRequestAttributes::LAST_USERNAME, $username);
        }
        $this->checkTheFormToken($request);
        if ($username === '' || $password === '') {
            throw new BadCredentialsException('The login carries no username or no password.');
        }
        try {
            $credential = $this->verification->verify(
                $this->tenants->provide(),
                $username,
                $password,
                $this->contexts->fromRequest($request),
            );
        } catch (AuthenticationFailedException $exception) {
            throw new BadCredentialsException('The login was refused.', previous: $exception);
        }
        $user = new SecurityUser($credential->user, $credential);

        return new Passport(
            new UserBadge($credential->user->username, static fn (): SecurityUser => $user),
            new VerifiedPassword($password),
        );
    }

    /**
     * The token of AbstractAuthenticator, which a readonly class cannot extend.
     */
    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        return new PostAuthenticationToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles());
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): Response
    {
        return $this->handler->onAuthenticationSuccess($request, $token);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return $this->handler->onAuthenticationFailure($request, $exception);
    }

    /**
     * Where the firewall sends a browser that reached something it is not signed in for. The pages of this
     * plane decide for themselves whether a session is needed, so nothing of the provider asks for this; it
     * is what a firewall of several authenticators must name, and the honest answer is the login page.
     */
    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return $this->pages->redirectToPage(LoginController::ROUTE, $request);
    }

    public function isInteractive(): bool
    {
        return true;
    }

    /**
     * @throws InvalidCsrfTokenException
     */
    private function checkTheFormToken(Request $request): void
    {
        $token = new CsrfToken(self::CSRF_TOKEN_ID, $request->request->getString(self::CSRF_TOKEN_PARAMETER));
        if (! $this->csrfTokens->isTokenValid($token)) {
            throw new InvalidCsrfTokenException('Invalid CSRF token.');
        }
    }
}
