<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Fixture;

use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\VerifiedJws;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidJwsException;
use Beffroi\Core\Port\JwsVerifierInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use function sprintf;

final class FakeJwsVerifier implements JwsVerifierInterface
{
    /**
     * @var array<string, array{Tenant, string, array<string, string>}> compact JWS => tenant, payload, header
     */
    private array $known = [];

    /**
     * @param array<string, string> $header the members beyond "alg" and "kid"
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
        $key = new TenantKey(
            'fake-kid',
            $tenant,
            Algorithms::rs256(),
            [
                'kid' => 'fake-kid',
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'n' => 'AQAB',
                'e' => 'AQAB',
            ],
            'sealed',
            Fixtures::now(),
            Fixtures::now(),
        );

        return new VerifiedJws(
            $key,
            $header
            + [
                'alg' => 'RS256',
                'kid' => 'fake-kid',
            ],
            $payload,
        );
    }
}
