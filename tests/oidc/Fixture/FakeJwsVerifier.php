<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Fixture;

use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Key\VerifiedJws;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidJwsException;
use Heidi\Core\Port\JwsVerifierInterface;
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
     * @var array<string, array{Tenant, string}> compact JWS => tenant and payload
     */
    private array $known = [];

    public function knows(Tenant $tenant, string $compactJws, string $payload): void
    {
        $this->known[$compactJws] = [$tenant, $payload];
    }

    public function verify(Tenant $tenant, string $compactJws): VerifiedJws
    {
        [$issuer, $payload] = $this->known[$compactJws] ?? [null, null];
        if ($issuer === null || $payload === null || ! $issuer->equals($tenant)) {
            throw new InvalidJwsException(sprintf('The token "%s" does not verify.', $compactJws));
        }
        $key = new SigningKey('fake-kid', $tenant, SignatureAlgorithm::RS256, [
            'kid' => 'fake-kid',
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => 'AQAB',
            'e' => 'AQAB',
        ], 'sealed', Fixtures::now());

        return new VerifiedJws($key, [
            'alg' => 'RS256',
            'kid' => 'fake-kid',
        ], $payload);
    }
}
