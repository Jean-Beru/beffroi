<?php

declare(strict_types=1);

namespace App\Push;

use DateTimeImmutable;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use function max;

/**
 * What a browser of this provider is shown and where it is sent when it is tapped: three strings and
 * nothing else, so that what the service worker renders is what this wrote and never what a third party
 * did (BCP 10027 §5.2).
 *
 * It carries no identifier of anything and no link that answers anything: the address is the page of the
 * provider where a user finds what is waiting for them, found there by who they are. A notification that
 * could be followed straight into an approval is the attack that page exists to make impossible.
 *
 * It is encrypted to the browser before it leaves (RFC 8291), so what a push service sees of it is its
 * length; how long it is worth delivering is the request it is about and not a constant (RFC 8030 §5.2).
 */
final readonly class PushMessage
{
    public function __construct(
        public string $title,
        public string $body,
        public string $url,
        public DateTimeImmutable $worthDeliveringUntil,
    ) {
    }

    /**
     * RFC 8030 §5.2: the seconds a push service keeps the message for a browser that is not connected.
     * Never negative, and zero is deliver-now-or-not-at-all, which is what a request about to expire
     * deserves.
     *
     * @return int<0, max>
     */
    public function timeToLive(DateTimeImmutable $now): int
    {
        return max(0, $this->worthDeliveringUntil->getTimestamp() - $now->getTimestamp());
    }

    /**
     * What the service worker reads.
     */
    public function payload(): string
    {
        return json_encode([
            'title' => $this->title,
            'body' => $this->body,
            'url' => $this->url,
        ], JSON_THROW_ON_ERROR);
    }
}
