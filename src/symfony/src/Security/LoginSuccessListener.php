<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use function array_map;
use DateInterval;
use DateTimeImmutable;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\BrowserSession;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Application\Authentication\SessionTerminator;
use Heidi\Core\Domain\Event\UserAuthenticated;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Core\Port\CredentialRepositoryInterface;
use LogicException;
use Psr\EventDispatcher\EventDispatcherInterface;
use function sprintf;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Uid\Uuid;

/**
 * Opens the session of the core after a login of the firewall and binds the browser to it (architecture
 * §3.2, §5.4). A re-login records a proof on the session the browser holds rather than opening another;
 * a browser bound to someone else's session ends it first. The proofs are copied into the token of
 * Symfony (symfony/symfony#66064).
 */
final readonly class LoginSuccessListener
{
    public function __construct(
        private TenantProvider $tenants,
        private BrowserSession $browser,
        private AuthenticationSessionRepositoryInterface $sessions,
        private CredentialRepositoryInterface $credentials,
        private SessionTerminator $terminator,
        private RequestContextFactory $contexts,
        private EventDispatcherInterface $events,
        private DateInterval $sessionLifetime = new DateInterval('PT12H'),
    ) {
    }

    #[AsEventListener]
    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();
        if (! $user instanceof SecurityUser) {
            return;
        }
        $method = self::method($event->getPassport());
        $request = $event->getRequest();
        $context = $this->contexts->fromRequest($request);
        $now = $context->receivedAt;
        $tenant = $this->tenants->provide();

        $session = $this->browser->authenticationSession($request, $tenant);
        if ($session !== null && $session->user->id->equals($user->id)) {
            $session->recordProof($method, $context);
            $this->sessions->save($session);
        } else {
            if ($session !== null) {
                $this->terminator->end($session, SessionEnd::User, $context);
            }
            $session = new AuthenticationSession(
                Uuid::v7(),
                $tenant,
                $user->user(),
                $now,
                AuthenticationProofs::of($method, $now),
                $context,
                $now->add($this->sessionLifetime),
            );
            $this->sessions->save($session);
            $this->events->dispatch(new UserAuthenticated($session));
        }

        $credential = $user->passwordCredential();
        if ($credential !== null && $method->equals(AuthenticationMethod::password())) {
            $credential->markUsed($now);
            $this->credentials->save($credential);
        }

        $this->browser->bind($request->getSession(), $session);
        $event->getAuthenticatedToken()
            ->setAuthenticationProofs(array_map(
                static fn (DateTimeImmutable $provenAt): int => $provenAt->getTimestamp(),
                $session->proofs->entries,
            ));
    }

    /**
     * A firewall that authenticates another way is refused loudly rather than recorded wrongly.
     */
    private static function method(Passport $passport): AuthenticationMethod
    {
        if ($passport->hasBadge(PasswordCredentials::class)) {
            return AuthenticationMethod::password();
        }

        throw new LogicException(sprintf('The firewall authenticated a user of the bundle without a method the bundle knows: no "%s" badge on the passport.', PasswordCredentials::class));
    }
}
