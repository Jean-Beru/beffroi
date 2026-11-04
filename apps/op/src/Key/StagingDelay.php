<?php

declare(strict_types=1);

namespace App\Key;

use DateInterval;
use function is_int;
use function preg_match;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * How long a staged key is published before it signs (architecture §3.3, §9): unless configured, the
 * max-age of the JWK Set plus the refetch cooldown of oidc_login. The max-age is what the delay must cover,
 * measured (issue #59): a relying party that fetches the JWK Set from the OP holds no copy older than that
 * when the key starts signing. The cooldown is the margin for a copy that came late through a shared HTTP
 * cache (the JWK Set is public): such a party refetches on the unknown "kid" once its copy is that old.
 *
 * Not configured is null, or an empty string, which is what an environment variable declared empty gives: the
 * delay of a deployment that names none follows the max-age it names, so the two cannot drift apart.
 */
final readonly class StagingDelay
{
    /**
     * OidcSignatureVerifier::ROTATION_COOLDOWN of Symfony's oidc_login: on an unknown "kid", the JWK Set
     * is refetched once if the copy is this old at least, and the token is refused otherwise.
     */
    public const int ROTATION_COOLDOWN = 60;

    /**
     * @param int|string|null $configured a number of seconds, the digits an environment variable carries, or nothing for the derived delay
     *
     * @throws InvalidConfigurationException when what is configured is no number of seconds
     */
    public static function seconds(int|string|null $configured, int $jwksMaxAge): int
    {
        if ($configured === null || $configured === '') {
            return $jwksMaxAge + self::ROTATION_COOLDOWN;
        }
        if (is_int($configured) ? $configured < 0 : preg_match('/^\d+$/D', $configured) !== 1) {
            throw new InvalidConfigurationException(sprintf(
                'The "beffroi" configuration key "staging_delay" is a number of seconds, or nothing for the max-age of the JWK Set plus %d, "%s" given.',
                self::ROTATION_COOLDOWN,
                $configured,
            ));
        }

        return (int) $configured;
    }

    /**
     * @param int|string|null $configured a number of seconds, the digits an environment variable carries, or nothing for the derived delay
     *
     * @throws InvalidConfigurationException when what is configured is no number of seconds
     */
    public static function interval(int|string|null $configured, int $jwksMaxAge): DateInterval
    {
        return new DateInterval('PT' . self::seconds($configured, $jwksMaxAge) . 'S');
    }
}
