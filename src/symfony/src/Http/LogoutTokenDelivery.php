<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use function sprintf;

/**
 * What one attempt at delivering a logout token came back with (Back-Channel Logout 1.0 §2.8). Three
 * outcomes, because the sender has three things to do with them: done, give up now, try again later.
 * The specification names two codes as final, 400 and 501; anything else it does not name is treated as
 * a failure that may still pass, because a relying party that is restarting or deploying answers that
 * way for a minute and then works.
 */
final readonly class LogoutTokenDelivery
{
    private function __construct(
        public bool $delivered,
        public bool $final,
        public string $detail,
    ) {
    }

    /**
     * §2.8: the relying party answers 200 OK when it logged the session out.
     */
    public static function delivered(int $status): self
    {
        return new self(true, true, sprintf('the client answered %d', $status));
    }

    /**
     * §2.8: 400 when it found the request invalid, 501 when it does not implement the logout. Neither
     * changes on a retry; a redirect does not either, and no outbound request follows one (decision 0006).
     */
    public static function refused(string $detail): self
    {
        return new self(false, true, $detail);
    }

    /**
     * A 5xx, a timeout, a connection refused: the client may be back in a minute.
     */
    public static function unreachable(string $detail): self
    {
        return new self(false, false, $detail);
    }
}
