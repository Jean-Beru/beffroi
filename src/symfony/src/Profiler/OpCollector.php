<?php

declare(strict_types=1);

namespace Heidi\Bundle\Profiler;

use function array_map;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;
use Throwable;

/**
 * The panel of the provider in the profiler and in the debug toolbar (issue #152): what the request
 * brought, which client it named, what the endpoint decided and what left. It collects nothing by
 * itself; it copies what the observers of this namespace recorded while the request was served.
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
                'heading' => $observation->heading,
                'entries' => $observation->entries,
            ], $this->profile->observations()),
        ];
    }

    /**
     * @return list<array{heading: string, entries: array<string, string>}>
     */
    public function getObservations(): array
    {
        /** @var list<array{heading: string, entries: array<string, string>}> $observations */
        $observations = $this->data['observations'] ?? [];

        return $observations;
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
