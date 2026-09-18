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
 * A login the firewall refused, announced as AuthenticationFailed (architecture §3.4, §3.5). Only the
 * login page of the bundle is listened to.
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
     * The cause behind "bad credentials"; anything else is not an attempt on an account.
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
     * The badge is not asked to load again what it could not load the first time.
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
