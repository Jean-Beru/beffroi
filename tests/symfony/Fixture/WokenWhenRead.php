<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

/**
 * An object a header of the transport should never bring to life: it counts every time unserialize() builds one.
 */
final class WokenWhenRead
{
    public static int $woken = 0;

    public function __wakeup(): void
    {
        ++self::$woken;
    }
}
