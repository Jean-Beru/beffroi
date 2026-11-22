<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use function array_filter;
use function array_values;
use function count;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CodeAttemptLimiterInterface;
use Beffroi\Core\Port\PasswordAttemptLimiterInterface;
use const PHP_INT_MAX;

final class FakeAttemptLimiter implements CodeAttemptLimiterInterface, PasswordAttemptLimiterInterface
{
    /**
     * @var list<string>
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
