<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Key\VerifiedJws;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Port\JwsVerifierInterface;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use function sprintf;

/**
 * A verifier that knows a few tokens by heart: the ones it was given verify, with the payload it was
 * given for them, in the tenant it was given them for; every other token is invalid. Never leaves the
 * test suite.
 */
final class FakeJwsVerifier implements JwsVerifierInterface
{
    /**
     * @var array<string, array{Tenant, string, array<string, string>}> compact JWS => tenant, payload and the header members beyond "alg" and "kid"
     */
    private array $known = [];

    /**
     * @param array<string, string> $header the protected header members beyond "alg" and "kid", "typ" for one
     */
    public function knows(Tenant $tenant, string $compactJws, string $payload, array $header = []): void
    {
        $this->known[$compactJws] = [$tenant, $payload, $header];
    }

    public function verify(Tenant $tenant, string $compactJws): VerifiedJws
    {
        [$issuer, $payload, $header] = $this->known[$compactJws] ?? [null, null, []];
        if ($issuer === null || $payload === null || ! $issuer->equals($tenant)) {
            throw new InvalidJwsException(sprintf('The token "%s" does not verify.', $compactJws));
        }
        $key = new SigningKey('fake-kid', $tenant, Algorithms::rs256(), [
            'kid' => 'fake-kid',
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => 'AQAB',
            'e' => 'AQAB',
        ], 'sealed', Fixtures::now(), Fixtures::now());

        return new VerifiedJws($key, $header + [
            'alg' => 'RS256',
            'kid' => 'fake-kid',
        ], $payload);
    }
}
