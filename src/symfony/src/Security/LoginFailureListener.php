<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Http\RequestContextFactory;
use Heidi\Core\Domain\Event\AuthenticationFailed;
use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Throwable;

/**
 * A login the firewall refused, announced to the core the way the core announces its own refusals
 * (AuthenticationFailed, architecture §3.4, §3.5): the reason, the identifier as typed and the user it
 * named, when it named one, go to the audit trail; the user is told nothing more than "failed". Only
 * the login page of the bundle is listened to: the failures of a host application are its own.
 */
final readonly class LoginFailureListener
{
    public function __construct(
        private TenantProvider $tenants,
        private RequestContextFactory $contexts,
        private EventDispatcherInterface $events,
    ) {
    }

    #[AsEventListener]
    public function onLoginFailure(LoginFailureEvent $event): void
    {
        $request = $event->getRequest();
        $passport = $event->getPassport();
        $badge = $passport?->getBadge(UserBadge::class);
        if ($request->attributes->get('_route') !== 'heidi_interaction_login' || $passport === null || ! $badge instanceof UserBadge) {
            return;
        }
        $reason = self::reason($event->getException(), $passport);
        if ($reason === null) {
            return;
        }
        $context = $this->contexts->fromRequest($request);
        $this->events->dispatch(new AuthenticationFailed(
            $context->receivedAt,
            $this->tenants->provide(),
            $context,
            AuthenticationMethod::password(),
            $reason,
            $badge->getUserIdentifier(),
            $reason === AuthenticationFailureReason::UnknownUser ? null : self::securityUser($passport)?->user(),
        ));
    }

    /**
     * The reason the firewall hides from the user: an unknown user and a disabled account are wrapped in
     * "bad credentials" before they reach here, the cause is behind it. Anything else (a form token, a
     * malformed request) is not an attempt on an account and is not recorded as one.
     */
    private static function reason(AuthenticationException $exception, Passport $passport): ?AuthenticationFailureReason
    {
        for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
            if ($cause instanceof UserNotFoundException) {
                return AuthenticationFailureReason::UnknownUser;
            }
            if ($cause instanceof DisabledException) {
                return AuthenticationFailureReason::DisabledUser;
            }
        }
        if (! $exception instanceof BadCredentialsException) {
            return null;
        }
        $user = self::securityUser($passport);
        if ($user === null) {
            return null;
        }

        return $user->getPassword() === null ? AuthenticationFailureReason::NoSuchCredential : AuthenticationFailureReason::InvalidCredential;
    }

    /**
     * The user the passport loaded, when it loaded one of the bundle; the badge is not asked to load
     * again what it could not load the first time.
     */
    private static function securityUser(Passport $passport): ?SecurityUser
    {
        try {
            $user = $passport->getUser();
        } catch (AuthenticationException) {
            return null;
        }

        return $user instanceof SecurityUser ? $user : null;
    }
}
