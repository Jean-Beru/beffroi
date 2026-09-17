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
 * The bridge between a login of the firewall and a session of the core (architecture §3.2, §5.4). The
 * firewall verified the credentials; what the core needs is a session that says who, since when, how and
 * from where: it is opened here, with the proof the passport carried, the request context, and a
 * lifetime; the browser is bound to it (BrowserSession) and its pending interactions stay with it.
 *
 * A user who signs in again in a browser already bound to their session, because a client asked for a
 * fresh login (prompt=login, max_age), does not open a second session: the proof is recorded on the one
 * they have, which moves its auth_time and leaves the tokens issued on it alone. A browser bound to the
 * session of someone else ends that session first: two users do not share a cookie.
 *
 * The proofs of the session are copied into the token of Symfony (symfony/symfony#66064), method by
 * method with the moment each was last proven, so that what the firewall calls recent
 * (IS_AUTHENTICATED_RECENTLY, symfony/symfony#66014) and what OIDC Core §2 calls auth_time are read
 * from one record; the most recent entry is that auth_time.
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
     * What was proven, from what the passport carried: a password today. A firewall that authenticates
     * a user of the bundle another way must say how, or the session would claim a method it has no
     * proof of; until it can, it is refused loudly rather than recorded wrongly.
     */
    private static function method(Passport $passport): AuthenticationMethod
    {
        if ($passport->hasBadge(PasswordCredentials::class)) {
            return AuthenticationMethod::password();
        }

        throw new LogicException(sprintf('The firewall authenticated a user of the bundle without a method the bundle knows: no "%s" badge on the passport.', PasswordCredentials::class));
    }
}
