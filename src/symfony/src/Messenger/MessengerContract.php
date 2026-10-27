<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Messenger;

use Beffroi\Bundle\Message\Command;
use Beffroi\Bundle\Message\Event;
use Beffroi\Bundle\Message\Notification;
use Beffroi\Bundle\Message\Query;
use Beffroi\Bundle\Message\SyncMessage;
use Beffroi\Core\Domain\Event\DomainEventInterface;

/**
 * The buses of this provider, their middleware and where each marker is sent (architecture §5.6), written
 * here and prepended by the bundle (issue #456).
 *
 * **It is a contract and not a preference.** `doctrine_transaction` is what makes a use case one unit of
 * work, and the default middleware of Messenger, which no bus here turns off, is what makes an event
 * announced from a handler leave after the transaction of that handler committed
 * (`dispatch_after_current_bus`): an installation that wires the three buses itself and gets either wrong
 * breaks the asynchronous half of the provider, and it breaks it quietly, in the half nothing in a browser
 * shows. So the bundle says it and an application is left with what is actually its own, the transports,
 * which is where a broker and its credentials live.
 *
 * **One marker, one transport.** Messenger sends a message to every transport its class, its parents and
 * its interfaces are routed to, so two markers on one class send it twice. That is why each marker below
 * appears once, and why a message that must be handled in the request implements `SyncMessage` and never
 * `Command`.
 *
 * **The default transport is the database, a queue per lane.** A new installation needs no broker to
 * work: every lane is a queue of its own in `doctrine://default` unless `BEFFROI_MESSENGER_DSN` names
 * something else, `{lane}` in that DSN being where the name of each lane goes (`LaneDsn`), so that one
 * variable moves the four lanes and keeps them four. A deployment that wants one lane on a broker and
 * another in the database declares that transport itself, which is the one part of this block an
 * application still owns.
 *
 * **What leaves the process is sealed** (decision 0020): the serializer of the bundle is the default one
 * of every transport, so a body on a broker, and a body in the table of a transport, is a JWE to the
 * message key of the tenant. It is in the contract and not left to a deployment for the same reason the
 * middleware is: a transport that named the serializer of the component would carry in the clear what
 * every column of this provider seals at rest, and nothing in a browser would show it.
 */
final readonly class MessengerContract
{
    /**
     * Where a lane goes unless a deployment says otherwise. The database, because a provider that cannot
     * be installed without RabbitMQ is a provider nobody tries, and a queue of it per lane, because four
     * lanes in one queue are one lane.
     */
    public const string DEFAULT_DSN = 'doctrine://default?queue_name=' . LaneDsn::PLACEHOLDER;

    public const string DSN_ENVIRONMENT_VARIABLE = 'BEFFROI_MESSENGER_DSN';

    /**
     * Where what the provider fails to handle lands, and the one lane that is not the DSN of a deployment:
     * a failure transport on the broker that failed is a failure transport nobody reads.
     */
    public const string FAILURE_DSN = 'doctrine://default?queue_name=failed';

    public const string DEFAULT_BUS = 'command.bus';

    public const string FAILURE_TRANSPORT = 'failed';

    /**
     * What seals a body on its way out and opens it on its way in, for every transport: the failure one
     * included, which is the transport that keeps what it is given the longest.
     */
    public const string SERIALIZER = 'beffroi.messenger.serializer';

    /**
     * The lanes, by priority and then by what they carry, each named by what asks for it: the three of our
     * own writes, and the one of what the provider carries to somebody it does not own.
     *
     * @var list<string>
     */
    public const array LANES = ['async_priority_high', 'async_priority_medium', 'async_priority_low', 'async_notifications'];

    /**
     * What `command.bus` runs a message through, in order. Each one is here because a handler of this
     * provider needs it: `doctrine_transaction` makes a use case one unit of work, `router_context`
     * restores the request context so that a URL built in a worker is the absolute URL of this issuer,
     * and the two connection middleware are what lets a worker run for days.
     *
     * `validation` is not here, although the application carried it: it needs `symfony/validator`, which
     * this bundle does not require and an installation may not have, and the messages of this provider
     * are final classes without logic that carry no constraint for it to check. An application that
     * validates its own messages adds it to this bus itself.
     *
     * **What is here is what the defaults do not carry.** `default_middleware` stays enabled, so Messenger
     * puts `add_bus_name_stamp_middleware`, `dispatch_after_current_bus` and
     * `failed_message_processing_middleware` in front of this list and `handle_message` behind it: an event
     * announced from a handler leaves after that handler committed without this list naming it, and naming
     * it again would run it twice (issue #493).
     *
     * @var list<string>
     */
    public const array COMMAND_MIDDLEWARE = [
        'router_context',
        'doctrine_ping_connection',
        'doctrine_close_connection',
        'doctrine_transaction',
    ];

    /**
     * Where each marker is sent. The events of the core and of the module are routed by the interface they
     * all implement, so an event added to either package leaves the process without a line here.
     *
     * @return array<class-string, string>
     */
    public static function routing(): array
    {
        return [
            Command::class => 'async_priority_medium',
            Event::class => 'async_priority_low',
            DomainEventInterface::class => 'async_priority_low',
            Notification::class => 'async_notifications',
            Query::class => 'sync',
            SyncMessage::class => 'sync',
        ];
    }

    /**
     * The whole block, as the bundle prepends it: an application that declares a transport of the same
     * name keeps its own, a prepended configuration being the one that is merged first.
     *
     * @return array<string, mixed>
     */
    public static function configuration(): array
    {
        $transports = ['sync' => 'sync://'];
        foreach (self::LANES as $lane) {
            $transports[$lane] = [
                'dsn' => LaneDsn::of($lane, self::DSN_ENVIRONMENT_VARIABLE),
                // what the provider carries to a third party is tried again on the patience the bundle
                // writes, which also bounds how long a logout token stays on its way and so how long a
                // signing key is held back from retiring (§3.3, §4.9): two places that must agree are one
                'retry_strategy' => $lane === 'async_notifications'
                    ? ['service' => NotificationRetryPolicy::class]
                    : ['max_retries' => 4, 'delay' => 1000, 'max_delay' => 30_000, 'multiplier' => 4],
            ];
        }
        $transports[self::FAILURE_TRANSPORT] = self::FAILURE_DSN;

        return [
            'default_bus' => self::DEFAULT_BUS,
            'failure_transport' => self::FAILURE_TRANSPORT,
            'serializer' => [
                'default_serializer' => self::SERIALIZER,
            ],
            'transports' => $transports,
            'routing' => self::routing(),
            'buses' => [
                'query.bus' => null,
                'command.bus' => [
                    'middleware' => self::COMMAND_MIDDLEWARE,
                ],
                // Nothing of its own: the defaults carry the deferral it needs, and "allow_no_handlers"
                // is what lets an event nothing listens to yet be announced all the same.
                'event.bus' => [
                    'default_middleware' => 'allow_no_handlers',
                ],
            ],
        ];
    }
}
