<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Closure;
use Doctrine\Deprecations\Deprecation;

final class DoctrineDeprecations
{
    /**
     * @param Closure(): mixed $call
     *
     * @return array<string, int>
     */
    public static function raisedWhile(Closure $call): array
    {
        Deprecation::enableTrackingDeprecations();
        $before = Deprecation::getTriggeredDeprecations();
        $call();
        $raised = [];
        foreach (Deprecation::getTriggeredDeprecations() as $identifier => $count) {
            $times = $count - ($before[$identifier] ?? 0);
            if ($times > 0) {
                $raised[$identifier] = $times;
            }
        }

        return $raised;
    }
}
