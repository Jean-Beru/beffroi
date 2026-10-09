<?php

declare(strict_types=1);

namespace App\Demonstration\Trace;

use function array_key_exists;
use DateTimeImmutable;

/**
 * What one flow of one client exchanged (issue #462), in the order it exchanged it. The trace belongs
 * to the demonstration and is keyed by the flow it traces and by the client that played it: five rungs
 * of the ladder are five clients playing one flow, and each has its own.
 *
 * Beside the hops it holds what the client of a live run is holding between two of them, the device
 * code it is polling on, the token it is about to introspect. Those are never drawn: they are what lets
 * the next hop be made at all, and what is drawn is the hop they produced.
 */
final readonly class FlowTrace
{
    /**
     * @param list<TracedHop>       $hops
     * @param array<string, string> $holdings
     */
    public function __construct(
        public string $grantType,
        public string $clientId,
        public DateTimeImmutable $startedAt,
        public array $hops = [],
        private array $holdings = [],
    ) {
    }

    public function with(TracedHop $hop): self
    {
        return new self($this->grantType, $this->clientId, $this->startedAt, [...$this->hops, $hop], $this->holdings);
    }

    /**
     * @param array<string, string> $holdings what the client now holds, merged into what it held
     */
    public function holding(array $holdings): self
    {
        return new self($this->grantType, $this->clientId, $this->startedAt, $this->hops, [...$this->holdings, ...$holdings]);
    }

    public function holds(string $name): ?string
    {
        return array_key_exists($name, $this->holdings) ? $this->holdings[$name] : null;
    }

    public function drew(string $hop): bool
    {
        foreach ($this->hops as $traced) {
            if ($traced->hop === $hop) {
                return true;
            }
        }

        return false;
    }

    /**
     * How many times a hop was taken, which is what a polled token request is read by.
     */
    public function times(string $hop): int
    {
        $times = 0;
        foreach ($this->hops as $traced) {
            if ($traced->hop === $hop) {
                ++$times;
            }
        }

        return $times;
    }
}
