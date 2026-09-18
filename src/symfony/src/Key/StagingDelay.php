<?php

declare(strict_types=1);

namespace Heidi\Bundle\Key;

use DateInterval;

/**
 * How long a staged key is published before it signs (architecture §3.3, §9): unless configured, the
 * max-age of the JWK Set plus the refetch cooldown of oidc_login, so that a relying party with a warm
 * cache, even one that just refetched on a forged "kid", sees the new key when it starts signing.
 */
final readonly class StagingDelay
{
    /**
     * OidcSignatureVerifier::ROTATION_COOLDOWN of Symfony's oidc_login: one refetch of the JWK Set per
     * minute on an unknown "kid".
     */
    public const int ROTATION_COOLDOWN = 60;

    public static function seconds(?int $configured, int $jwksMaxAge): int
    {
        return $configured ?? $jwksMaxAge + self::ROTATION_COOLDOWN;
    }

    public static function interval(?int $configured, int $jwksMaxAge): DateInterval
    {
        return new DateInterval('PT' . self::seconds($configured, $jwksMaxAge) . 'S');
    }
}
