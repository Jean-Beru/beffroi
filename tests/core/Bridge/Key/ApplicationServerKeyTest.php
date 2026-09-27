<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\Key;

use function array_map;
use Heidi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Domain\Key\GeneratedKeyPair;
use Heidi\Core\Domain\Key\KeyAlgorithmInterface;
use Heidi\Core\Domain\Key\TenantKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\KeyNotFoundException;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8292 §2, architecture §3.3: a key the tenant hands out itself is a key of the tenant in every way
 * but one, and that one is that its issuer does not publish it.
 */
final class ApplicationServerKeyTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private SealedKeyProvider $provider;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->provider = new SealedKeyProvider($this->keys, Keys::sealer());
    }

    /**
     * RFC 7517 §5: the JWK Set is what the tenant publishes to whoever reads its issuer, and a key it
     * hands to a browser itself is not part of that.
     */
    #[Test]
    public function theJwkSetDoesNotCarryAKeyTheTenantHandsOut(): void
    {
        // Given
        $signing = $this->activeKey(Algorithms::rs256(), Keys::pair());
        $this->activeKey(Algorithms::vapid(), Keys::applicationServerPair());

        // When
        $published = $this->provider->publicKeys($this->tenant);

        // Then
        static::assertSame(
            [$signing->kid],
            array_map(static fn (TenantKey $key): string => $key->kid, $published->keys),
        );
    }

    /**
     * §3.2: what a browser is handed to subscribe under is the active key of that algorithm.
     */
    #[Test]
    public function theActiveKeyIsWhatABrowserIsHanded(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::vapid(), Keys::applicationServerPair());

        // When / Then
        static::assertSame($key, $this->provider->activeApplicationServerKey($this->tenant, Algorithms::vapid()));
    }

    /**
     * §4.2: a push is signed by the key its subscription was made under, so a key that has retired is
     * one no subscription of it can be pushed to any more.
     */
    #[Test]
    public function aKeyThatHasRetiredOpensNothing(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::vapid(), Keys::applicationServerPair());
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->keys->save($key);

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('hands out no key');

        // When
        $this->provider->applicationServerKey($this->tenant, $key->kid);
    }

    /**
     * The use is asserted and not deduced from the caller: a key the issuer publishes is not one it
     * hands to a browser, whoever asks for it under that name.
     */
    #[Test]
    public function aKeyOfTheJwkSetIsNotHandedOut(): void
    {
        // Given
        $signing = $this->activeKey(Algorithms::rs256(), Keys::pair());

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('is published in its JWK Set');

        // When
        $this->provider->applicationServerKey($this->tenant, $signing->kid);
    }

    private function activeKey(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $key->activate(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }
}
