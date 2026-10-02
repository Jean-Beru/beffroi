<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Client;

use DateTimeImmutable;
use function hash;
use Beffroi\Bundle\Cache\SeenOnce;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\RequestObjectReplayGuardInterface;
use function sprintf;

/**
 * The "jti" of the request objects already seen (CIBA Core §7.1.1), so that a signed request is made
 * once. What makes a "jti" unique is all this says; remembering it once is SeenOnce's, with the caveat
 * that goes with a pool.
 */
final readonly class RequestObjectReplayGuard implements RequestObjectReplayGuardInterface
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
     * Per tenant and per client: it is the client that signs an object that chooses the "jti" of it, and
     * two clients may choose the same one.
     */
    private static function key(Client $client, string $jti): string
    {
        return 'beffroi.request_objects.' . hash('xxh128', sprintf('%s|%s|%s', $client->tenant->id->toRfc4122(), $client->registration->clientId, $jti));
    }
}
