<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Key;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §3.3, RFC 7638
 */
final class SealedKeyProviderTest extends TestCase
{
    /**
     * RFC 7517 §4.5
     */
    #[Test]
    public function aKeyOpenedForOneTenantIsNeverTheAnswerForAnother(): void
    {
        // Given
        $acme = Fixtures::tenant('acme', 'https://id.acme.example');
        $globex = Fixtures::tenant('globex', 'https://id.globex.example');
        $keys = new InMemoryTenantKeyRepository();
        $keys->save(self::activeKey($acme, Keys::pair()));
        $keys->save(self::activeKey($globex, Keys::pair()));
        $provider = new SealedKeyProvider($keys, Keys::opened());
        $provider->activeKey($acme, Algorithms::rs256());

        // When
        $answer = $provider->activeKey($globex, Algorithms::rs256());

        // Then
        static::assertTrue($answer->key->tenant->equals($globex));
    }

    private static function activeKey(Tenant $tenant, GeneratedKeyPair $pair): TenantKey
    {
        $now = Fixtures::now();
        $key = new TenantKey(
            $pair->kid,
            $tenant,
            $pair->algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($tenant, $pair->privateJwk),
            $now,
            $now,
        );
        $key->activate($now);

        return $key;
    }
}
