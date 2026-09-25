<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Bundle\Controller\LoginController;
use DateTimeImmutable;
use Heidi\Core\Domain\Event\AuthenticationFailureReason;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\RequestContext;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * The form login of the firewall (architecture §5.4): a password, "pwd" (RFC 8176 §2), and nothing else.
 * The code that may follow it is the TOTP login's to declare, and the two together are what the policy
 * of the tenant reads as two factors.
 */
final readonly class PasswordLogin implements AnnouncesItsRefusalInterface, DatesItsCredentialInterface
{
    public function __construct(
        private DatedPasswordCredential $passwords,
    ) {
    }

    public function proofs(Passport $passport): ?array
    {
        return $passport->hasBadge(PasswordCredentials::class) ? [AuthenticationMethod::password()] : null;
    }

    public function everyProvableMethod(): array
    {
        return [AuthenticationMethod::password()];
    }

    public function recordUse(Passport $passport, SecurityUser $user, DateTimeImmutable $now, RequestContext $context): bool
    {
        if ($this->proofs($passport) === null) {
            return false;
        }
        $this->passwords->of($user, $now);

        return true;
    }

    public function route(): string
    {
        return LoginController::ROUTE;
    }

    /**
     * The cause behind "bad credentials"; anything else is not an attempt on an account. A user nobody
     * knows is never named as the user of the refusal, only as the name that was typed.
     */
    public function refusal(AuthenticationException $exception, ?Passport $passport): ?LoginFailure
    {
        $badge = $passport?->getBadge(UserBadge::class);
        if ($passport === null || ! $badge instanceof UserBadge) {
            return null;
        }
        $user = self::securityUser($passport);
        $reason = AuthenticationFailureCause::of($exception);
        if ($reason === null) {
            if (! $exception instanceof BadCredentialsException || $user === null) {
                return null;
            }
            $reason = $user->getPassword() === null ? AuthenticationFailureReason::NoSuchCredential : AuthenticationFailureReason::InvalidCredential;
        }

        return new LoginFailure(
            AuthenticationMethod::password(),
            $reason,
            $badge->getUserIdentifier(),
            $reason === AuthenticationFailureReason::UnknownUser ? null : $user?->user(),
        );
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
