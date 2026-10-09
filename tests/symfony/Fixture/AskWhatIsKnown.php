<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Fixture;

use Beffroi\Bundle\Message\Query;

/**
 * Stands in for a `Query` of the bundle, a read, which the contract routes to `sync` where nothing is
 * serialized: it is here because a marker is routed by the contract and not by a deployment, and a
 * deployment that moved this lane to a transport would have its reads sealed like everything else
 * (decision 0020).
 */
final readonly class AskWhatIsKnown implements Query
{
    public function __construct(
        public string $about,
    ) {
    }
}
