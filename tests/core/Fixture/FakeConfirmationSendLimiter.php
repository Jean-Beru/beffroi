<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Fixture;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ConfirmationSendLimiterInterface;
use function count;
use const PHP_INT_MAX;

final class FakeConfirmationSendLimiter implements ConfirmationSendLimiterInterface
{
    /**
     * @var list<array{string, string}> the person and the address of each send counted
     */
    public private(set) array $sends = [];

    public function __construct(
        private readonly int $allowed = PHP_INT_MAX,
    ) {
    }

    public function spend(User $user, string $address): bool
    {
        $this->sends[] = [$user->id->toRfc4122(), $address];

        return count($this->sends) <= $this->allowed;
    }
}
