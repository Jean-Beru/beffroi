<?php

declare(strict_types=1);

namespace App\Http;

use function sprintf;

/**
 * What one attempt at carrying something to a third party came back with (architecture §5.6): a logout
 * token to a relying party, the word that a backchannel request has been answered to the client that
 * made it. Three outcomes, because the sender has three things to do with them: done, give up now, try
 * again later, and they are the same three whatever was carried.
 *
 * Which answers are final is the specification of what was carried, and is decided by the sender that
 * knows it. What is not named as final is treated as a failure that may still pass, because a third
 * party that is restarting or deploying answers that way for a minute and then works.
 */
final readonly class OutboundDelivery
{
    private function __construct(
        public bool $delivered,
        public bool $final,
        public string $detail,
    ) {
    }

    /**
     * Anything in the 2xx range: it was taken.
     */
    public static function delivered(int $status): self
    {
        return new self(true, true, sprintf('the client answered %d', $status));
    }

    /**
     * An answer that says the third party read what was sent and will not take it, and that says the
     * same thing on a retry. A redirect is one of them, no outbound request following one (decision
     * 0006).
     */
    public static function refused(string $detail): self
    {
        return new self(false, true, $detail);
    }

    /**
     * A 5xx, a timeout, a connection refused: the third party may be back in a minute.
     */
    public static function unreachable(string $detail): self
    {
        return new self(false, false, $detail);
    }
}
