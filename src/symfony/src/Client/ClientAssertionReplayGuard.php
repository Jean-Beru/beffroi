<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Client;

use DateTimeImmutable;
use function hash;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\ClientAssertionReplayGuardInterface;
use Beffroi\Bundle\Cache\SeenOnce;
use function sprintf;

/**
 * The "jti" of the client assertions already seen (RFC 7523 §3, §4), so that an assertion authenticates
 * once. What makes a "jti" unique is all this says; remembering it once is SeenOnce's, with the caveat
 * that goes with a pool.
 */
final readonly class ClientAssertionReplayGuard implements ClientAssertionReplayGuardInterface
{
    public function __construct(
        private SeenOnce $seen,
    ) {
    }

    public function remember(Client $client, string $jti, DateTimeImmutable $expiresAt): bool
    {
        return $this->seen->remember(self::key($client, $jti), $expiresAt);
    }

    /**
     * Per tenant and per client: RFC 7523 §3 makes a "jti" unique to the issuer of the assertion, and
     * two clients may use the same one.
     */
    private static function key(Client $client, string $jti): string
    {
        return 'beffroi.client_assertions.' . hash('xxh128', sprintf('%s|%s|%s', $client->tenant->id->toRfc4122(), $client->registration->clientId, $jti));
    }
}
