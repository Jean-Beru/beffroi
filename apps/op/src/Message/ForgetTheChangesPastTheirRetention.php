<?php

declare(strict_types=1);

namespace App\Message;

/**
 * The timed step that forgets the changes of a record kept long enough (issue #482, architecture §5.6).
 * It carries nothing: the duration is the configuration's and the tenant is the one of the process.
 */
final readonly class ForgetTheChangesPastTheirRetention implements Command
{
}
