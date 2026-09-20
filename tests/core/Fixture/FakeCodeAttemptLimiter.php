<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use function array_filter;
use function count;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\CodeAttemptLimiterInterface;
use const PHP_INT_MAX;

/**
 * Counts the attempts of each user and refuses past the number allowed, without a clock: a window that
 * never slides, enough to see that the use case asks before it verifies.
 */
final class FakeCodeAttemptLimiter implements CodeAttemptLimiterInterface
{
    /**
     * @var list<string> the users of every attempt, in order
     */
    public private(set) array $attempts = [];

    public function __construct(
        private readonly int $allowed = PHP_INT_MAX,
    ) {
    }

    public function attempt(User $user): bool
    {
        $id = $user->id->toRfc4122();
        $this->attempts[] = $id;

        return count(array_filter($this->attempts, static fn (string $attempt): bool => $attempt === $id)) <= $this->allowed;
    }
}
