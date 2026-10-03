<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Message;

/**
 * The timed step that forgets the archives a person asked for and that have expired (issue #453,
 * architecture §5.6). It carries nothing: every row holds the date it goes away on, and the tenant is the
 * one of the process.
 */
final readonly class ForgetTheExpiredArchives implements Command
{
}
