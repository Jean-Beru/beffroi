<?php

declare(strict_types=1);

namespace Heidi\Bundle\Trust;

use DateTimeImmutable;
use function hash;
use Heidi\Bundle\Cache\SeenOnce;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Trust\TrustedIssuer;
use Heidi\Oidc\Port\IssuerAssertionReplayGuardInterface;
use function sprintf;

/**
 * The "jti" of the assertions a trusted issuer has already had exchanged (RFC 7523 §3), so that one assertion
 * is exchanged once. What makes a "jti" unique is all this says; remembering it once is SeenOnce's, with the
 * caveat that goes with a pool.
 *
 * It has a pool of its own and shares none with the assertions that authenticate a client: an assertion
 * remembered as an authorization must not be able to satisfy the guard of an authentication or the other way
 * round (RFC 7523 §2.1).
 */
final readonly class IssuerAssertionReplayGuard implements IssuerAssertionReplayGuardInterface
{
    public function __construct(
        private SeenOnce $seen,
    ) {
    }

    public function remember(Tenant $tenant, TrustedIssuer $issuer, string $jti, DateTimeImmutable $expiresAt): bool
    {
        return $this->seen->remember(self::key($tenant, $issuer, $jti), $expiresAt);
    }

    /**
     * Per tenant and per issuer: RFC 7523 §3 makes a "jti" unique to the issuer of the assertion, and two
     * issuers may use the same one, as may the same issuer for two tenants.
     */
    private static function key(Tenant $tenant, TrustedIssuer $issuer, string $jti): string
    {
        return 'heidi.issuer_assertions.' . hash('xxh128', sprintf('%s|%s|%s', $tenant->id->toRfc4122(), $issuer->issuer, $jti));
    }
}
