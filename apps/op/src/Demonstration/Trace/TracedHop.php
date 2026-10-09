<?php

declare(strict_types=1);

namespace App\Demonstration\Trace;

use DateTimeImmutable;

/**
 * One hop of a flow as it really happened (issue #462): the hop of the picture it fills, when it
 * happened, and what travelled. A hop is a request or an answer, never both: a request hop carries the
 * method and the address it was sent to, an answer hop the status it came back with.
 *
 * Nothing is built here from what a flow was supposed to exchange. A hop exists because somebody sent
 * it or answered it, which is why a drawing of a trace cannot show a payload that did not travel.
 */
final readonly class TracedHop
{
    private function __construct(
        public string $hop,
        public DateTimeImmutable $at,
        public string $payload,
        public ?string $method,
        public ?string $url,
        public ?int $status,
        public bool $failed,
        public ?string $reason,
    ) {
    }

    public static function sent(string $hop, DateTimeImmutable $at, string $method, string $url, string $payload): self
    {
        return new self($hop, $at, $payload, $method, $url, null, false, null);
    }

    /**
     * An answer, and whether the flow went on after it: a status of 400 or more, or a body naming an
     * error of RFC 6749 §5.2, is a hop that failed, and the reason it gives is the one drawn beside it.
     */
    public static function answered(string $hop, DateTimeImmutable $at, int $status, string $payload, ?string $reason = null): self
    {
        return new self($hop, $at, $payload, null, null, $status, $status >= 400 || $reason !== null, $reason);
    }

    /**
     * A hop a run tried to take and could not take at all: nothing was answered because nothing was
     * reached. What is drawn is the reason, and no payload, because none travelled.
     */
    public static function unreachable(string $hop, DateTimeImmutable $at, string $reason): self
    {
        return new self($hop, $at, '', null, null, null, true, $reason);
    }
}
