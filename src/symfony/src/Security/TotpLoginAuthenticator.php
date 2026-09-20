<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Bundle\Controller\LoginCodeController;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\InteractionPages;
use Heidi\Bundle\Http\PendingLoginStore;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Authentication\AuthenticationFailedException;
use Heidi\Core\Application\Totp\TotpAuthentication;
use Heidi\Core\Port\UserRepositoryInterface;
use function is_string;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * The second step of a login on the firewall of the interaction pages (architecture §5.4): the code the
 * code page posts, with the same CSRF token as the login page, for the login the SecondFactorGate held
 * in this browser. The code is verified by TotpAuthentication of the core, which counts the attempt,
 * accepts a code once or spends a backup code, and announces the outcome itself: the failure listener
 * of the bundle has nothing to add on this route. The passport carries what both steps proved
 * (TotpCredentials) for the one LoginSuccessListener; a success sends the browser back to the login
 * page of its interaction, which resumes it; a failure, back to the code page with one flat message,
 * the pending login kept for another try within its lifetime. A KMS that does not open the secret is no
 * failure of the login: the exception of the core goes on as it came, to the KmsUnavailableListener, the
 * pending login kept for the same code once the KMS is back.
 */
final readonly class TotpLoginAuthenticator implements AuthenticatorInterface, InteractiveAuthenticatorInterface
{
    public const string CSRF_TOKEN_ID = 'authenticate';

    public const string CSRF_TOKEN_PARAMETER = '_csrf_token';

    public const string CODE_PARAMETER = '_code';

    public function __construct(
        private TenantProvider $tenants,
        private PendingLoginStore $pendingLogins,
        private UserRepositoryInterface $users,
        private TotpAuthentication $authentication,
        private RequestContextFactory $contexts,
        private InteractionLoginHandler $handler,
        private InteractionPages $pages,
    ) {
    }

    public function supports(Request $request): bool
    {
        return $request->isMethod('POST') && $request->attributes->get('_route') === LoginCodeController::ROUTE;
    }

    public function authenticate(Request $request): Passport
    {
        $code = $request->request->get(self::CODE_PARAMETER);
        $token = $request->request->get(self::CSRF_TOKEN_PARAMETER);
        if (! is_string($code) || $code === '') {
            throw new AuthenticationException('The login carries no code.');
        }
        $context = $this->contexts->fromRequest($request);
        $login = $this->pendingLogins->pending($request->getSession(), $context->receivedAt) ?? throw new AuthenticationException('No login is pending for this browser.');
        $tenant = $this->tenants->provide();
        $user = $this->users->find($login->userId);
        if ($user === null || ! $user->tenant->equals($tenant)) {
            throw new AuthenticationException('The pending login names no user of this tenant.');
        }
        try {
            $method = $this->authentication->authenticate($user, $code, $context);
        } catch (AuthenticationFailedException $exception) {
            throw new BadCredentialsException('The code was refused.', previous: $exception);
        }

        return new Passport(
            new UserBadge($user->username),
            new TotpCredentials($login, $method),
            [new CsrfTokenBadge(self::CSRF_TOKEN_ID, is_string($token) ? $token : null)],
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
        $this->pendingLogins->forget($request->getSession());

        return $this->handler->onAuthenticationSuccess($request, $token);
    }

    /**
     * Kept where the security component keeps it, for the code page to read once.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $request->getSession()
            ->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return $this->pages->redirectToPage(LoginCodeController::ROUTE, $request);
    }

    public function isInteractive(): bool
    {
        return true;
    }
}
