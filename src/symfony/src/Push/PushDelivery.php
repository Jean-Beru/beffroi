<?php

declare(strict_types=1);

namespace Heidi\Bundle\Push;

use function sprintf;

/**
 * What one push to one browser came back with (RFC 8030 §5): the push service took it, the subscription
 * is gone, or the push service did not answer for it. Three outcomes, because there are three things to
 * do with them, and only the middle one is a fact about the subscription rather than about the attempt.
 *
 * "Gone" is 404 and 410 and nothing else (§7.3): a push service says with them that the subscription it
 * once handed out is not one any more, which is the one answer that means the row should stop being
 * tried. Every other refusal is about this attempt and may pass on the next.
 */
final readonly class PushDelivery
{
    private function __construct(
        public bool $delivered,
        public bool $gone,
        public string $detail,
    ) {
    }

    public static function delivered(int $status): self
    {
        return new self(true, false, sprintf('the push service answered %d', $status));
    }

    /**
     * RFC 8030 §7.3: the subscription is not one any more, and the browser has to make another. It is
     * also what a subscription whose application server key has retired is, learned here rather than
     * from a push service: the request this provider would sign is one that service would refuse
     * (RFC 8292 §4.2).
     */
    public static function gone(string $detail): self
    {
        return new self(false, true, $detail);
    }

    public static function unreachable(string $detail): self
    {
        return new self(false, false, $detail);
    }
}
