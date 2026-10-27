<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use Beffroi\Bundle\Http\ByteLimit;
use Beffroi\Bundle\Http\Timeout;
use DateInterval;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * A number the tree holds to bounds, as the container builds the value a service is handed: a number of seconds made
 * an interval, the time a call to a third party is given, the bytes it may answer. The tree refuses a number out of
 * its bounds when the container is compiled; a number an environment variable carries is one only at runtime, so the
 * same bounds refuse it here, the first time a service it is handed to is built, rather than let a deployment write
 * past the maximum a specification recommends, a lifetime that is expired when it starts, or a call that waits for
 * ever.
 */
final readonly class BoundedNumber
{
    /**
     * A number of seconds made an interval: a lifetime, a second at least, or a leeway or a cooldown, which the tree
     * lets be none.
     *
     * @param string $key the node the number was written under, which the refusal names
     * @param int|null $maximum the bound the tree holds that node to, null where it names none
     * @param int $minimum the floor the tree holds that node to
     *
     * @throws InvalidConfigurationException when the number of seconds is below the floor or above the maximum
     */
    public static function interval(int $seconds, string $key, ?int $maximum = null, int $minimum = 1): DateInterval
    {
        if ($seconds < $minimum || $maximum !== null && $seconds > $maximum) {
            throw new InvalidConfigurationException(
                $maximum === null
                    ? self::belowItsFloor($key, 'seconds', (string) $minimum, (string) $seconds)
                    : sprintf('The "beffroi" configuration key "%s" is a number of seconds from %d to %d, %d given.', $key, $minimum, $maximum, $seconds),
            );
        }

        return new DateInterval('PT' . $seconds . 'S');
    }

    /**
     * The time one call to a third party is given, a tenth of a second at least: none would be a call that waits for
     * ever, HttpClient reading a "max_duration" of zero as no limit at all.
     *
     * @throws InvalidConfigurationException when the number of seconds is below the floor
     */
    public static function timeout(float $seconds, string $key): Timeout
    {
        if ($seconds < Timeout::MINIMUM) {
            throw new InvalidConfigurationException(self::belowItsFloor($key, 'seconds', (string) Timeout::MINIMUM, (string) $seconds));
        }

        return new Timeout($seconds);
    }

    /**
     * The bytes a third party may answer before the read stops, one at least.
     *
     * @throws InvalidConfigurationException when the number of bytes is below one
     */
    public static function bytes(int $bytes, string $key): ByteLimit
    {
        self::assertAtLeast($bytes, 1, $key, 'bytes');

        return new ByteLimit($bytes);
    }

    /**
     * A number an object holds itself to as the tree holds the node it was written under, for an object the number
     * reaches as it is (LoadBudget, NotificationRetryPolicy).
     *
     * @param string $unit what the number counts, as the refusal names it
     *
     * @throws InvalidConfigurationException when the number is below the floor
     */
    public static function assertAtLeast(int $number, int $minimum, string $key, string $unit): void
    {
        if ($number < $minimum) {
            throw new InvalidConfigurationException(self::belowItsFloor($key, $unit, (string) $minimum, (string) $number));
        }
    }

    private static function belowItsFloor(string $key, string $unit, string $minimum, string $given): string
    {
        return sprintf('The "beffroi" configuration key "%s" is a number of %s of at least %s, %s given.', $key, $unit, $minimum, $given);
    }
}
