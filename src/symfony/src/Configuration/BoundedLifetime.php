<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use DateInterval;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * A lifetime the tree bounds on both sides (TokensSection), as the container builds it. The tree refuses a
 * number out of its bounds when the container is compiled; a number an environment variable carries is one
 * only at runtime, so the same bounds refuse it here, the first time a service it is handed to is built,
 * rather than let a deployment write past the maximum a specification recommends.
 */
final readonly class BoundedLifetime
{
    /**
     * @param string $key the node of "beffroi.tokens" the number was written under, which the refusal names
     * @param int $maximum the bound the tree holds that node to
     *
     * @throws InvalidConfigurationException when the number of seconds is below one or above the maximum
     */
    public static function interval(int $seconds, string $key, int $maximum): DateInterval
    {
        if ($seconds < 1 || $seconds > $maximum) {
            throw new InvalidConfigurationException(sprintf(
                'The "beffroi" configuration key "%s" is a number of seconds from 1 to %d, %d given.',
                $key,
                $maximum,
                $seconds,
            ));
        }

        return new DateInterval('PT' . $seconds . 'S');
    }
}
