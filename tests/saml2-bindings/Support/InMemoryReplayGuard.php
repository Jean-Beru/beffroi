<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Bindings\Tests\Support;

use Beffroi\Saml2\Model\Port\ReplayGuardInterface;
use DateTimeImmutable;

/**
 * model.md section 5.2, section 9.1, M-11
 */
final class InMemoryReplayGuard implements ReplayGuardInterface
{
    /**
     * @var array<string, array<string, DateTimeImmutable>> when each ID of each issuer may be forgotten
     */
    private array $remembered = [];

    public function remember(string $issuer, string $id, DateTimeImmutable $expiresAt): bool
    {
        if ($this->expiresAt($issuer, $id) instanceof DateTimeImmutable) {
            return false;
        }
        $this->remembered[$issuer][$id] = $expiresAt;

        return true;
    }

    public function expiresAt(string $issuer, string $id): ?DateTimeImmutable
    {
        return $this->remembered[$issuer][$id] ?? null;
    }

    /**
     * M-11
     */
    public function isEmpty(): bool
    {
        return $this->remembered === [];
    }
}
