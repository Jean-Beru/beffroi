<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Fixture;

use Beffroi\Bundle\Message\Event;

/**
 * Stands in for an `Event` of the bundle, the one marker of the contract that nothing of this provider
 * carries yet: what happened in the bundle rather than in the core, which announces its own in PSR-14.
 *
 * It exists so that every marker a transport is routed to is a message something writes to a transport in
 * a test (decision 0020): the serializer reads no marker, and this is what holds that to being true rather
 * than being assumed.
 */
final readonly class SomethingHappened implements Event
{
    public function __construct(
        public string $what,
    ) {
    }
}
