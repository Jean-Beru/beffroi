<?php

declare(strict_types=1);

namespace App\Message;

/**
 * The timed step that drops the rows which can no longer do anything (issue #177, architecture §5.6):
 * spent codes nothing descends from any more, refresh tokens whose family is over, expired access tokens,
 * interactions, pushed requests and sessions. Recurring and idempotent: a tick that finds nothing due does
 * nothing, a tick that leaves a backlog is caught up by the next.
 */
final readonly class ForgetTheRecordsThatAreDead implements Command
{
}
