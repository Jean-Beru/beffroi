<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Configuration;

use DateInterval;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * The lifetime a refresh token is renewed for at each rotation, which no rotation may carry past the
 * absolute lifetime of its family (architecture §4.6). The tree checks the two numbers when both are
 * written down; a number an environment variable carries is one only at runtime, where the issuer of the
 * refresh tokens is handed the sliding lifetime through here, so the rule is checked again then.
 */
final readonly class SlidingRefreshLifetime
{
    /**
     * @throws InvalidConfigurationException when the sliding lifetime exceeds the absolute one
     */
    public static function assertWithin(int $sliding, int $absolute): void
    {
        if ($sliding > $absolute) {
            throw new InvalidConfigurationException('The sliding lifetime of a refresh token (refresh_token_ttl) cannot exceed the absolute lifetime of its family (refresh_token_absolute_ttl).');
        }
    }

    /**
     * @throws InvalidConfigurationException when the sliding lifetime exceeds the absolute one
     */
    public static function interval(int $sliding, int $absolute): DateInterval
    {
        self::assertWithin($sliding, $absolute);

        return new DateInterval('PT' . $sliding . 'S');
    }
}
