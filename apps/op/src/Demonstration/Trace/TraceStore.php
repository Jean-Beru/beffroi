<?php

declare(strict_types=1);

namespace App\Demonstration\Trace;

use function array_filter;
use function array_slice;
use function array_values;
use function hash;
use function is_array;
use function is_string;
use function preg_replace;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\InvalidArgumentException;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * Where the demonstration keeps what it saw (issue #462): one trace per flow and per client, and, per
 * flow, the clients that played it, the one that played it last first.
 *
 * That second reading is what a hop the provider cannot attribute by itself goes to. A browser typing a
 * device code names no client, and neither does a browser answering a backchannel request: the request
 * says which flow it belongs to, and the trace it joins is the one of the client that last played that
 * flow. One run at a time is what a demonstration is, and that is the reading it is exact for.
 *
 * It is also what tells the five rungs of a ladder apart: five clients playing one flow are five
 * traces, each replayed on its own.
 *
 * Not a store of the provider: it holds what a lab exchanged with itself, it lives in a cache pool of
 * its own, and it is wired in development and in the suite of the application and nowhere else.
 */
final readonly class TraceStore
{
    /**
     * Long enough for a flow to be played, read and replayed, short enough that a desk left alone
     * forgets what it was shown.
     */
    public const int LIFETIME = 3600;

    /**
     * How many clients of one flow are remembered: the rungs of the ladder and a little room.
     */
    public const int CLIENTS = 12;

    public function __construct(
        private CacheItemPoolInterface $traces,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @throws InvalidArgumentException
     */
    public function of(string $grantType, string $clientId): ?FlowTrace
    {
        $item = $this->traces->getItem(self::key($grantType, $clientId));
        $trace = $item->isHit() ? $item->get() : null;

        return $trace instanceof FlowTrace ? $trace : null;
    }

    /**
     * The clients that played that flow, the one that played it last first.
     *
     * @throws InvalidArgumentException
     *
     * @return list<string>
     */
    public function clientsOf(string $grantType): array
    {
        $item = $this->traces->getItem(self::clientsKey($grantType));
        $clients = $item->isHit() ? $item->get() : null;

        return is_array($clients) ? array_values(array_filter($clients, static fn (mixed $client): bool => is_string($client))) : [];
    }

    /**
     * The trace a hop naming no client joins: the one of the client that last played the flow.
     *
     * @throws InvalidArgumentException
     */
    public function lastOf(string $grantType): ?FlowTrace
    {
        $clients = $this->clientsOf($grantType);

        return $clients === [] ? null : $this->of($grantType, $clients[0]);
    }

    /**
     * @throws InvalidArgumentException
     */
    public function opened(string $grantType, string $clientId): FlowTrace
    {
        return $this->save(new FlowTrace($grantType, $clientId, $this->clock->now()));
    }

    /**
     * What a client exchanged in that flow, forgotten: a replay started over shows nothing until the
     * flow is played again.
     *
     * @throws InvalidArgumentException
     */
    public function forget(string $grantType, string $clientId): void
    {
        $this->traces->deleteItem(self::key($grantType, $clientId));
    }

    /**
     * @throws InvalidArgumentException
     */
    public function save(FlowTrace $trace): FlowTrace
    {
        $this->keep(self::key($trace->grantType, $trace->clientId), $trace);
        $this->keep(
            self::clientsKey($trace->grantType),
            array_slice(
                [
                    $trace->clientId,
                    ...array_filter(
                        $this->clientsOf($trace->grantType),
                        static fn (string $client): bool => $client !== $trace->clientId,
                    ),
                ],
                0,
                self::CLIENTS,
            ),
        );

        return $trace;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function keep(string $key, mixed $value): void
    {
        $item = $this->traces->getItem($key);
        $item->set($value);
        $item->expiresAfter(self::LIFETIME);
        $this->traces->save($item);
    }

    /**
     * A key of the cache carries none of the characters PSR-6 reserves, and a grant type is named by an
     * absolute URI often enough that a flow is keyed by a digest of its name rather than by it.
     */
    private static function key(string $grantType, string $clientId): string
    {
        return sprintf(
            'beffroi_demonstration.%s.%s',
            hash('xxh128', $grantType),
            preg_replace('/[^A-Za-z0-9_.-]/', '_', $clientId) ?? '',
        );
    }

    private static function clientsKey(string $grantType): string
    {
        return sprintf('beffroi_demonstration.clients.%s', hash('xxh128', $grantType));
    }
}
