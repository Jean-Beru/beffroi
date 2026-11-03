<?php

declare(strict_types=1);

namespace App\EndSession;

use Beffroi\Oidc\Domain\EndSession\LogoutChannel;

/**
 * What tells the clients of an ended session that it ended, one per channel (architecture §4.9): the
 * thing that does the work says which channel it is, so that a deployment that does not wire it stops
 * announcing it (issue #98).
 */
interface LogoutChannelInterface
{
    public function channel(): LogoutChannel;
}
