<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Fixture;

use Beffroi\Bundle\Message\Command;
use Symfony\Component\Uid\Uuid;

/**
 * Stands in for the message the asynchronous enrichment of a provenance will carry.
 *
 * The enrichment itself does not exist: the port is there (`GeoLocatorInterface`) with a bridge that
 * locates nothing, and nothing calls it. What this exists to prove is the thing that decides whether it
 * can exist at all: a sealed column written from a handler of the bus, with no request anywhere, reaches
 * the scope of its tenant (decision 0018). A `Command` because that is what a write whose result no
 * request needs is.
 */
final readonly class EnrichTheProvenance implements Command
{
    public function __construct(
        public Uuid $sessionId,
    ) {
    }
}
