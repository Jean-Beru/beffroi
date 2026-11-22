<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Support;

use Beffroi\Saml2\Model\Port\ReplayGuardInterface;
use DateTimeImmutable;

/**
 * Section 5.2, M-11
 */
final class InMemoryReplayGuard implements ReplayGuardInterface
{
    /**
     * @var array<string, array<string, DateTimeImmutable>> expiry by issuer, then by ID
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
     * M-11, §9.3
     */
    public function isEmpty(): bool
    {
        return $this->remembered === [];
    }
}
