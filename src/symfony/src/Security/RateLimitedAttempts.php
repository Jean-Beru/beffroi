<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\CodeAttemptLimiterInterface;
use Heidi\Core\Port\PasswordAttemptLimiterInterface;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

/**
 * The attempts of a user, counted by a rate limiter of Symfony keyed by the identifier of the user and
 * nothing else: one instance per limiter the bundle declares in the framework (five in a sliding window
 * of one minute, the sixth refused), the codes on "heidi_code_attempts" and the passwords on
 * "heidi_password_attempts", two counts kept in the cache pool of the rate limiters, shared by the
 * processes of the OP. The rule is the core's (decision 0006); the application does not tune it.
 */
final readonly class RateLimitedAttempts implements CodeAttemptLimiterInterface, PasswordAttemptLimiterInterface
{
    public const string CODE_LIMITER = 'heidi_code_attempts';

    public const string PASSWORD_LIMITER = 'heidi_password_attempts';

    /**
     * @var list<string>
     */
    public const array LIMITERS = [self::CODE_LIMITER, self::PASSWORD_LIMITER];

    public const int LIMIT = 5;

    public const string INTERVAL = '1 minute';

    public function __construct(
        private RateLimiterFactoryInterface $limiters,
    ) {
    }

    /**
     * The state of the window without a token taken from it, as the rate limiter reads it on zero tokens:
     * what it says then is how many tokens are left, never a refusal.
     */
    public function mayAttempt(User $user): bool
    {
        return $this->limiters->create($user->id->toRfc4122())
            ->consume(0)
            ->getRemainingTokens() > 0;
    }

    public function attempt(User $user): bool
    {
        return $this->limiters->create($user->id->toRfc4122())
            ->consume()
            ->isAccepted();
    }

    public function reset(User $user): void
    {
        $this->limiters->create($user->id->toRfc4122())
            ->reset();
    }
}
