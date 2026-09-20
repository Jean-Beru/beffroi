<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Bundle\Controller\PasskeyLoginController;
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
use Symfony\Component\Security\Core\Exception\TooManyLoginAttemptsAuthenticationException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Event\LoginFailureEvent;
use Throwable;

/**
 * A login the firewall refused, with a password or with a passkey, announced as AuthenticationFailed
 * (architecture §3.4, §3.5). Only the two login routes of the bundle are listened to.
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
        $route = $request->attributes->get('_route');
        $failure = match ($route) {
            'heidi_interaction_login' => self::passwordFailure($event->getException(), $event->getPassport()),
            PasskeyLoginController::ROUTE => self::passkeyFailure($event->getException(), $event->getPassport()),
            default => null,
        };
        if ($failure === null) {
            return;
        }
        $context = $this->contexts->fromRequest($request);
        $this->events->dispatch(new AuthenticationFailed(
            $context->receivedAt,
            $this->tenants->provide(),
            $context,
            $failure->method,
            $failure->reason,
            $failure->identifier,
            $failure->user,
        ));
    }

    /**
     * The cause behind "bad credentials"; anything else is not an attempt on an account.
     */
    private static function passwordFailure(AuthenticationException $exception, ?Passport $passport): ?LoginFailure
    {
        $badge = $passport?->getBadge(UserBadge::class);
        if ($passport === null || ! $badge instanceof UserBadge) {
            return null;
        }
        $user = self::securityUser($passport);
        $reason = self::reasonBehind($exception);
        if ($reason === null) {
            if (! $exception instanceof BadCredentialsException || $user === null) {
                return null;
            }
            $reason = $user->getPassword() === null ? AuthenticationFailureReason::NoSuchCredential : AuthenticationFailureReason::InvalidCredential;
        }

        return new LoginFailure(AuthenticationMethod::password(), $reason, $badge->getUserIdentifier(), $reason === AuthenticationFailureReason::UnknownUser ? null : $user?->user());
    }

    /**
     * What the authenticator of the bundle refused, with the reason it gave, or the account the checker
     * refused after the signature; nothing was typed, the identifier is null. A request without a pending
     * ceremony, without an assertion or without its form token is not an attempt on an account.
     */
    private static function passkeyFailure(AuthenticationException $exception, ?Passport $passport): ?LoginFailure
    {
        for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
            if ($cause instanceof PasskeyLoginException) {
                return new LoginFailure($cause->method, $cause->reason, null, $cause->user);
            }
        }
        $passkey = $passport?->getBadge(PasskeyCredentials::class);
        if (! $passkey instanceof PasskeyCredentials || self::reasonBehind($exception) !== AuthenticationFailureReason::DisabledUser) {
            return null;
        }
        $credential = $passkey->assertion->credential;

        return new LoginFailure($credential->methods($passkey->assertion->authenticatorData)[0], AuthenticationFailureReason::DisabledUser, null, $credential->user);
    }

    private static function reasonBehind(AuthenticationException $exception): ?AuthenticationFailureReason
    {
        for ($cause = $exception; $cause instanceof Throwable; $cause = $cause->getPrevious()) {
            if ($cause instanceof UserNotFoundException) {
                return AuthenticationFailureReason::UnknownUser;
            }
            if ($cause instanceof DisabledException) {
                return AuthenticationFailureReason::DisabledUser;
            }
            if ($cause instanceof TooManyLoginAttemptsAuthenticationException) {
                return AuthenticationFailureReason::TooManyAttempts;
            }
        }

        return null;
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
