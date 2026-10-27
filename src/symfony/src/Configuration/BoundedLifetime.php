<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use DateInterval;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * A lifetime the tree holds to a second at least and, where it names one, to a maximum (TokensSection,
 * LoadSection), as the container builds it. The tree refuses a number out of its bounds when the container
 * is compiled; a number an environment variable carries is one only at runtime, so the same bounds refuse it
 * here, the first time a service it is handed to is built, rather than let a deployment write past the
 * maximum a specification recommends or a lifetime that is expired when it starts.
 */
final readonly class BoundedLifetime
{
    /**
     * @param string $key the node the number was written under, which the refusal names
     * @param int|null $maximum the bound the tree holds that node to, null where it names none
     *
     * @throws InvalidConfigurationException when the number of seconds is below one or above the maximum
     */
    public static function interval(int $seconds, string $key, ?int $maximum = null): DateInterval
    {
        if ($seconds < 1 || $maximum !== null && $seconds > $maximum) {
            throw new InvalidConfigurationException(
                $maximum === null
                    ? sprintf('The "beffroi" configuration key "%s" is a number of seconds of at least 1, %d given.', $key, $seconds)
                    : sprintf('The "beffroi" configuration key "%s" is a number of seconds from 1 to %d, %d given.', $key, $maximum, $seconds),
            );
        }

        return new DateInterval('PT' . $seconds . 'S');
    }
}
