<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Message;

use Symfony\Component\Uid\Uuid;

/**
 * A person told this provider which language they read, on one of its pages (issue #471). A Command: it
 * waits on our own database and on nothing else.
 *
 * It names the person by identifier and carries the tag as a string, because that is what survives the
 * queue it is written to: a user is an entity of a tenant and does not leave the process whole, and the
 * language has already been read against the ones this deployment serves by the page that chose it.
 */
final readonly class RememberTheChosenLanguage implements Command
{
    public function __construct(
        public Uuid $user,
        public string $locale,
    ) {
    }
}
