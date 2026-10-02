<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Messenger;

use Beffroi\Bundle\Messenger\EventBusDispatcher;
use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Messenger\Stamp\DispatchAfterCurrentBusStamp;

final class EventBusDispatcherTest extends TestCase
{
    /**
     * Architecture §5.6: replayed on the event bus, to leave once the handler that announced it has
     * committed; PSR-14 asks for the event back.
     */
    #[Test]
    public function itReplaysTheEventOnTheBusAfterTheCurrentOne(): void
    {
        // Given
        $bus = new class() implements MessageBusInterface {
            /**
             * @var list<Envelope>
             */
            public array $envelopes = [];

            public function dispatch(object $message, array $stamps = []): Envelope
            {
                $this->envelopes[] = $envelope = Envelope::wrap($message, $stamps);

                return $envelope;
            }
        };
        $session = Fixtures::session();
        $session->end(SessionEnd::User, Fixtures::now());
        $event = new AuthenticationSessionEnded($session, Fixtures::now(), Fixtures::context());

        // When
        $returned = new EventBusDispatcher($bus)->dispatch($event);

        // Then
        static::assertSame($event, $returned);
        static::assertCount(1, $bus->envelopes);
        static::assertSame($event, $bus->envelopes[0]->getMessage());
        static::assertNotNull($bus->envelopes[0]->last(DispatchAfterCurrentBusStamp::class));
    }
}
