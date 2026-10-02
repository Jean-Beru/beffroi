<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Key;

use DateInterval;

/**
 * How long a staged key is published before it signs (architecture §3.3, §9): unless configured, the
 * max-age of the JWK Set plus the refetch cooldown of oidc_login. The max-age is what the delay must cover,
 * measured (issue #59): a relying party that fetches the JWK Set from the OP holds no copy older than that
 * when the key starts signing. The cooldown is the margin for a copy that came late through a shared HTTP
 * cache (the JWK Set is public): such a party refetches on the unknown "kid" once its copy is that old.
 */
final readonly class StagingDelay
{
    /**
     * OidcSignatureVerifier::ROTATION_COOLDOWN of Symfony's oidc_login: on an unknown "kid", the JWK Set
     * is refetched once if the copy is this old at least, and the token is refused otherwise.
     */
    public const int ROTATION_COOLDOWN = 60;

    public static function seconds(?int $configured, int $jwksMaxAge): int
    {
        return $configured ?? ($jwksMaxAge + self::ROTATION_COOLDOWN);
    }

    public static function interval(?int $configured, int $jwksMaxAge): DateInterval
    {
        return new DateInterval('PT' . self::seconds($configured, $jwksMaxAge) . 'S');
    }
}
