<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Fixture;

use function array_filter;
use function array_values;
use function count;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\CodeAttemptLimiterInterface;
use Heidi\Core\Port\PasswordAttemptLimiterInterface;
use const PHP_INT_MAX;

/**
 * Counts the attempts of each user and refuses past the number allowed, without a clock: a window that
 * never slides, enough to see that a use case asks before it verifies and forgets when it should. One
 * fixture for the two ports, as the bundle has one class for the two limiters.
 */
final class FakeAttemptLimiter implements CodeAttemptLimiterInterface, PasswordAttemptLimiterInterface
{
    /**
     * @var list<string> the users of every attempt still counted, in order
     */
    public private(set) array $attempts = [];

    public function __construct(
        private readonly int $allowed = PHP_INT_MAX,
    ) {
    }

    public function mayAttempt(User $user): bool
    {
        return $this->counted($user) < $this->allowed;
    }

    public function attempt(User $user): bool
    {
        $this->attempts[] = $user->id->toRfc4122();

        return $this->counted($user) <= $this->allowed;
    }

    public function reset(User $user): void
    {
        $id = $user->id->toRfc4122();
        $this->attempts = array_values(array_filter($this->attempts, static fn (string $attempt): bool => $attempt !== $id));
    }

    private function counted(User $user): int
    {
        $id = $user->id->toRfc4122();

        return count(array_filter($this->attempts, static fn (string $attempt): bool => $attempt === $id));
    }
}
