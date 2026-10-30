<?php

declare(strict_types=1);

namespace App\Demonstration\Live;

/**
 * A client of the demonstration, the one it plays a flow as (issue #462): its identifier, the secret it
 * authenticates with when it has one, what it asks for, and, for a flow whose user this provider goes
 * looking for, who that user is.
 *
 * These are the clients of the lab, the ones config/packages/dev/beffroi.yaml registers, and
 * the demonstration holds no client of its own: a flow it cannot play as anybody is a flow it says it
 * cannot play.
 */
final readonly class DemonstrationClient
{
    public function __construct(
        public string $id,
        public ?string $secret,
        public string $scope,
        public ?string $loginHint = null,
        public ?string $resource = null,
    ) {
    }
}
