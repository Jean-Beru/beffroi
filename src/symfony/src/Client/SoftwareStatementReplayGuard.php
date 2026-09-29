<?php

declare(strict_types=1);

namespace Heidi\Bundle\Client;

use DateTimeImmutable;
use function hash;
use Heidi\Bundle\Cache\SeenOnce;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Client\Registration\StatementIssuer;
use Heidi\Oidc\Port\SoftwareStatementReplayGuardInterface;
use function sprintf;

/**
 * The "jti" of the software statements a registration has already been made on (RFC 7591 §2.3), so that
 * one statement registers one client. What makes a "jti" unique is all this says; remembering it once is
 * SeenOnce's, with the caveat that goes with a pool.
 *
 * It has a pool of its own and shares none with the assertions a client authenticates with or presents as
 * an authorization: a statement remembered here must not be able to satisfy either of those guards, nor
 * the other way round (RFC 7523 §2.1).
 */
final readonly class SoftwareStatementReplayGuard implements SoftwareStatementReplayGuardInterface
{
    public function __construct(
        private SeenOnce $seen,
    ) {
    }

    public function remember(Tenant $tenant, StatementIssuer $issuer, string $jti, DateTimeImmutable $expiresAt): bool
    {
        return $this->seen->remember(self::key($tenant, $issuer, $jti), $expiresAt);
    }

    /**
     * Per tenant and per authority: a "jti" is unique to whoever signed the statement, and two authorities
     * may use the same one, as may the same authority for two tenants.
     */
    private static function key(Tenant $tenant, StatementIssuer $issuer, string $jti): string
    {
        return 'heidi.software_statements.' . hash('xxh128', sprintf('%s|%s|%s', $tenant->id->toRfc4122(), $issuer->issuer, $jti));
    }
}
