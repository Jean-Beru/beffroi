<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Message\SyncMessage;

/**
 * Stands in for a `SyncMessage`, a write the protocol needs the result of before answering, which the
 * contract routes to `sync` for that reason. Here for the same reason as AskWhatIsKnown: what the
 * serializer does with a message does not depend on which marker it carries.
 */
final readonly class WriteBeforeAnswering implements SyncMessage
{
    public function __construct(
        public string $what,
    ) {
    }
}
