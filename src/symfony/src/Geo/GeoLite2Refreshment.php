<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Geo;

use DateTimeImmutable;
use function sprintf;

/**
 * What one source of a refresh came to (issue #473): the sentence that says it, built where the outcome
 * is known, and whether the run must fail on it.
 *
 * Two fields and three ways to make one, because two callers render the same outcomes: a console prints
 * them and the weekly step logs them, and a sentence written in each would be the same sentence written
 * twice.
 */
final readonly class GeoLite2Refreshment
{
    private function __construct(
        public string $what,
        public bool $refused,
    ) {
    }

    public static function stored(string $source, string $edition, DateTimeImmutable $builtOn, int $nodes): self
    {
        return new self(
            sprintf(
                'The "%s" database of %s is stored: built on %s, a search tree of %d nodes.',
                $edition,
                $source,
                $builtOn->format('Y-m-d'),
                $nodes,
            ),
            false,
        );
    }

    /**
     * The source answered that what this deployment holds is what it serves, which is the answer a weekly
     * refresh gets most weeks and the reason it costs a request rather than a download.
     */
    public static function unchanged(string $source): self
    {
        return new self(sprintf('The database of %s is the one already stored, nothing was downloaded.', $source), false);
    }

    public static function refused(string $source, string $reason): self
    {
        return new self(sprintf('The archive of %s is refused, nothing of it is kept: %s', $source, $reason), true);
    }
}
