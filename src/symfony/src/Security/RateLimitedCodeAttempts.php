<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\CodeAttemptLimiterInterface;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;

/**
 * The attempts at a code, counted per user by the rate limiter of Symfony: the limiter "heidi_code_attempts"
 * the bundle declares in the framework (five in a sliding window of one minute, the sixth refused), kept
 * in the cache pool of the rate limiters, shared by the processes of the OP.
 */
final readonly class RateLimitedCodeAttempts implements CodeAttemptLimiterInterface
{
    public const string LIMITER = 'heidi_code_attempts';

    public const int LIMIT = 5;

    public const string INTERVAL = '1 minute';

    public function __construct(
        private RateLimiterFactoryInterface $limiters,
    ) {
    }

    public function attempt(User $user): bool
    {
        return $this->limiters->create($user->id->toRfc4122())
            ->consume()
            ->isAccepted();
    }
}
