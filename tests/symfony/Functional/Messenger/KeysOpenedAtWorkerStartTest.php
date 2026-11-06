<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Messenger;

use function array_map;
use App\Messenger\KeysOpenedAtWorkerStart;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use function is_array;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Messenger\Event\WorkerStartedEvent;

/**
 * Decision 0044
 */
final class KeysOpenedAtWorkerStartTest extends DatabaseTestCase
{
    #[Test]
    public function theConsumerOpensItsKeysWhenItStarts(): void
    {
        // When
        $listeners = self::service('event_dispatcher', EventDispatcherInterface::class)->getListeners(WorkerStartedEvent::class);

        // Then
        static::assertContains(
            self::service(KeysOpenedAtWorkerStart::class, KeysOpenedAtWorkerStart::class),
            array_map(static fn (mixed $listener): mixed => is_array($listener) ? $listener[0] : $listener, $listeners),
        );
    }
}
