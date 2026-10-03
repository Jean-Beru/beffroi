<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Message;

/**
 * The timed step that forgets the acts the journal has kept long enough (issue #454, architecture §5.6).
 * It carries nothing: the duration is the configuration's and the tenant is the one of the process.
 */
final readonly class ForgetTheActsPastTheirRetention implements Command
{
}
