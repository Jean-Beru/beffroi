<?php

declare(strict_types=1);

namespace Heidi\Bundle\Doctrine;

use RuntimeException;
use function sprintf;

/**
 * The row of the configured tenant is missing or disagrees with the configuration; nothing is served until it is.
 */
final class TenantNotSynchronizedException extends RuntimeException
{
    public static function missing(string $slug): self
    {
        return new self(sprintf('The tenant "%s" of the configuration has no row yet: synchronise it before serving requests.', $slug));
    }

    public static function differs(string $slug, string $field, string $stored, string $configured): self
    {
        return new self(sprintf(
            'The tenant "%s" is stored with the %s "%s" and configured with "%s": synchronise it before serving requests.',
            $slug,
            $field,
            $stored,
            $configured,
        ));
    }

    public static function issuerChangeRefused(string $slug, string $stored, string $configured): self
    {
        return new self(sprintf(
            'The tenant "%s" is stored with the issuer "%s" and the configuration now says "%s": the issuer of a tenant does not change, every token issued so far names it. Create another tenant under another slug.',
            $slug,
            $stored,
            $configured,
        ));
    }
}
