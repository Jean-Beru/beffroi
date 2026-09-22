<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use function array_map;
use function count;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Throwable;

/**
 * The panel of the provider in the profiler and in the debug toolbar (issue #152): what the request
 * brought, which interaction it belongs to, which client it named, what the endpoint decided, what left,
 * and what this provider serves. It collects nothing by itself; it copies what the observers of this
 * namespace recorded while the request was served, and groups them under the tabs they named.
 *
 * It is wired only when the kernel runs in debug, and it reports only on a request that reached an
 * endpoint of the provider, so a toolbar on any other page of the host application shows nothing.
 */
final class OpCollector extends DataCollector
{
    public const string NAME = 'heidi';

    public function __construct(
        private readonly OpProfile $profile,
    ) {
        $this->data = [];
    }

    public function collect(Request $request, Response $response, ?Throwable $exception = null): void
    {
        if (! $this->profile->hasTouchedTheProvider()) {
            return;
        }
        $this->data = [
            'observations' => array_map(static fn (Observation $observation): array => [
                'tab' => $observation->tab,
                'heading' => $observation->heading,
                'entries' => $observation->entries,
            ], $this->profile->observations()),
        ];
    }

    /**
     * @return list<array{tab: string, heading: string, entries: array<string, string>}>
     */
    public function getObservations(): array
    {
        /** @var list<array{tab: string, heading: string, entries: array<string, string>}> $observations */
        $observations = $this->data['observations'] ?? [];

        return $observations;
    }

    /**
     * The observations of the request under the tab each one named, the tabs in the order they were
     * first spoken of: a tab of the panel is a tab an observer asked for, never a list written here.
     *
     * @return array<string, list<array{heading: string, entries: array<string, string>}>>
     */
    public function getTabs(): array
    {
        $tabs = [];
        foreach ($this->getObservations() as $observation) {
            $tabs[$observation['tab']][] = [
                'heading' => $observation['heading'],
                'entries' => $observation['entries'],
            ];
        }

        return $tabs;
    }

    public function getCount(): int
    {
        return count($this->getObservations());
    }

    public function getName(): string
    {
        return self::NAME;
    }

    public function reset(): void
    {
        $this->data = [];
    }
}
