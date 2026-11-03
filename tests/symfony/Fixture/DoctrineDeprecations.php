<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use Closure;
use Doctrine\Deprecations\Deprecation;

/**
 * The deprecations of Doctrine a call raised, by their identifier, each with the number of times it was
 * raised.
 *
 * Doctrine counts every one and raises it once in a process, so the count is what is read: a call made after
 * another that raised the same deprecation would otherwise raise nothing. Counted whatever
 * DOCTRINE_DEPRECATIONS says: Doctrine reads it at the first deprecation of the process, which may come
 * before any kernel booted, and FrameworkBundle sets it when one does.
 */
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
