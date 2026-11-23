<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Key;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8292 §2, Architecture §3.3
 */
final class ApplicationServerKeyTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private OpenedKeys $opened;

    private SealedKeyProvider $provider;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->opened = Keys::opened();
        $this->provider = new SealedKeyProvider($this->keys, $this->opened);
    }

    /**
     * RFC 7517 §5
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
     * §3.2
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
     * §4.2
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

    #[Test]
    public function theMaterialOfAKeyThatHasRetiredLeavesTheProcess(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::vapid(), Keys::applicationServerPair());
        $opened = $this->provider->applicationServerKey($this->tenant, $key->kid);
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->keys->save($key);

        // When
        try {
            $this->provider->applicationServerKey($this->tenant, $key->kid);
        } catch (KeyNotFoundException) {
        }

        // Then
        static::assertNotSame($opened, $this->opened->open($this->tenant, $key));
    }

    #[Test]
    public function aKeyThatHasRetiredLeavesTheProcessWhenItsSuccessorIsOpened(): void
    {
        // Given
        $retired = $this->activeKey(Algorithms::vapid(), Keys::applicationServerPair());
        $opened = $this->provider->applicationServerKey($this->tenant, $retired->kid);
        $successor = $this->activeKey(Algorithms::vapid(), Keys::otherApplicationServerPair());
        $retired->startRetiring(Fixtures::now(), Fixtures::now());
        $retired->retire(Fixtures::now());
        $this->keys->save($retired);

        // When
        $this->provider->applicationServerKey($this->tenant, $successor->kid);

        // Then
        static::assertNotSame($opened, $this->opened->open($this->tenant, $retired));
    }

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
