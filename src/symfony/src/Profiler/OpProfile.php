<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use function array_any;
use Symfony\Contracts\Service\ResetInterface;

/**
 * What the provider did during the request being served, as the observers of this namespace record it.
 * One instance per request: a worker resets it between two of them, which is what the kernel does to
 * every resettable service.
 *
 * An observation nobody would tell from one already recorded is dropped: a client resolved twice in the
 * same request is one client, and a panel that says so twice says nothing more.
 */
final class OpProfile implements ResetInterface
{
    /**
     * @var list<Observation>
     */
    private array $observations = [];

    private bool $touched = false;

    public function record(Observation $observation): void
    {
        if (array_any($this->observations, static fn (Observation $recorded): bool => $recorded->isSameAs($observation))) {
            return;
        }
        $this->observations[] = $observation;
    }

    /**
     * Said once per request that reached an endpoint of the provider; nothing is reported for a request
     * that reached none, whatever an observer happened to see.
     */
    public function touch(): void
    {
        $this->touched = true;
    }

    public function hasTouchedTheProvider(): bool
    {
        return $this->touched;
    }

    /**
     * @return list<Observation>
     */
    public function observations(): array
    {
        return $this->observations;
    }

    public function reset(): void
    {
        $this->observations = [];
        $this->touched = false;
    }
}
