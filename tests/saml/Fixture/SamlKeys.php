<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Fixture;

use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use DateTimeImmutable;
use function is_string;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * SAML signing keys under test: RSA 2048, the floor of D-16, drawn once per process because RSA generation is slow,
 * and sealed by the local KMS of the core's suite as a tenant's keys are (S-1).
 */
final class SamlKeys
{
    private static ?GeneratedKeyPair $pair = null;

    private static ?GeneratedKeyPair $otherPair = null;

    private static ?GeneratedKeyPair $weakPair = null;

    public static function algorithm(): SamlSigning
    {
        return new SamlSigning();
    }

    public static function pair(): GeneratedKeyPair
    {
        return self::$pair ??= self::generate();
    }

    /**
     * A second pair of the same family, which is what a rotation stages beside the first.
     */
    public static function otherPair(): GeneratedKeyPair
    {
        return self::$otherPair ??= self::generate();
    }

    /**
     * A pair of 1 024 bits, under the floor of D-16, which Dsig refuses to sign with.
     */
    public static function weakPair(): GeneratedKeyPair
    {
        return self::$weakPair ??= self::generate(1024);
    }

    /**
     * A key of the tenant on that pair, staged, sealed by the KMS of the suite.
     */
    public static function key(
        Tenant $tenant,
        ?GeneratedKeyPair $pair = null,
        ?DateTimeImmutable $createdAt = null,
        ?KeyAlgorithmInterface $algorithm = null,
    ): TenantKey {
        $pair ??= self::pair();
        $createdAt ??= Fixtures::now();
        $algorithm ??= $pair->algorithm;

        return new TenantKey(
            $pair->kid,
            $tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($tenant, $pair->privateJwk),
            $createdAt,
            $createdAt,
        );
    }

    /**
     * The same key, active: what a tenant signs with today.
     */
    public static function activeKey(Tenant $tenant, ?GeneratedKeyPair $pair = null, ?DateTimeImmutable $createdAt = null): TenantKey
    {
        $key = self::key($tenant, $pair, $createdAt);
        $key->activate($createdAt ?? Fixtures::now());

        return $key;
    }

    /**
     * The key opened by the KMS of the suite, as the provider opens it to sign.
     */
    public static function opened(TenantKey $key): UnsealedKey
    {
        return new UnsealedKey($key, Keys::sealer()->unseal($key->tenant, $key->sealedPrivateJwk));
    }

    private static function generate(int $bits = 2048): GeneratedKeyPair
    {
        $algorithm = self::algorithm();
        $private = JWKFactory::createRSAKey($bits, [
            'alg' => $algorithm->name(),
            'use' => $algorithm->keyUse()->value,
        ]);
        $kid = $private->thumbprint('sha256');
        $private = new JWK([
            ...$private->all(),
            'kid' => $kid,
        ]);

        return new GeneratedKeyPair($kid, $algorithm, self::members($private), self::members($private->toPublic()));
    }

    /**
     * @return array<string, string>
     */
    private static function members(JWK $jwk): array
    {
        $members = [];
        foreach ($jwk->all() as $member => $value) {
            if (is_string($member) && is_string($value)) {
                $members[$member] = $value;
            }
        }

        return $members;
    }
}
