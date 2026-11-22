<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Key;

use function array_map;
use DateTimeImmutable;
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
 * Decision 0020, Architecture §3.3
 */
final class MessageKeyTest extends TestCase
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
    public function theJwkSetDoesNotCarryTheKeyMessagesAreSealedTo(): void
    {
        // Given
        $signing = $this->activeKey(Algorithms::rs256(), Keys::pair());
        $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());

        // When
        $published = $this->provider->publicKeys($this->tenant);

        // Then
        static::assertSame(
            [$signing->kid],
            array_map(static fn (TenantKey $key): string => $key->kid, $published->keys),
        );
    }

    #[Test]
    public function theKeyThatSealsCarriesItsPublicHalfAndItsPrivateHalfStaysSealed(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());

        // When
        $sealing = $this->provider->sealingKey($this->tenant, Algorithms::messageSeal());

        // Then
        static::assertSame($key, $sealing);
        static::assertSame(Keys::messagePair()->publicJwk, $sealing->publicJwk);
    }

    #[Test]
    public function aKeyThatIsStillStagedIsWhatSeals(): void
    {
        // Given
        $staged = $this->key(Algorithms::messageSeal(), Keys::messagePair());

        // When / Then
        static::assertSame($staged, $this->provider->sealingKey($this->tenant, Algorithms::messageSeal()));
    }

    #[Test]
    public function aSuccessorStagedForTheKeyTakesTheSealingOver(): void
    {
        // Given
        $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());
        $successor = $this->key(Algorithms::messageSeal(), Keys::otherMessagePair(), Fixtures::now()->modify('+90 days'));

        // When / Then
        static::assertSame($successor, $this->provider->sealingKey($this->tenant, Algorithms::messageSeal()));
    }

    #[Test]
    public function aKeyThatHasRetiredSealsNothing(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->keys->save($key);

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('holds no MESSAGE-SEAL key');

        // When
        $this->provider->sealingKey($this->tenant, Algorithms::messageSeal());
    }

    #[Test]
    public function aTenantWithNoKeySealsNothingAndIsToldWhichComesFirst(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" holds no MESSAGE-SEAL key: it is the first key a tenant is given, and nothing it writes to a transport leaves the process before it exists.');

        // When
        $this->provider->sealingKey($this->tenant, Algorithms::messageSeal());
    }

    #[Test]
    public function aKeyThatHasRetiredOpensNothing(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->keys->save($key);

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('seals nothing to');

        // When
        $this->provider->messageKey($this->tenant, $key->kid);
    }

    #[Test]
    public function theMaterialOfAKeyThatHasRetiredLeavesTheProcess(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());
        $opened = $this->provider->messageKey($this->tenant, $key->kid);
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->keys->save($key);

        // When
        try {
            $this->provider->messageKey($this->tenant, $key->kid);
        } catch (KeyNotFoundException) {
        }

        // Then
        static::assertNotSame($opened, $this->opened->open($this->tenant, $key));
    }

    #[Test]
    public function aKeyOfTheJwkSetDoesNotOpenAMessage(): void
    {
        // Given
        $encryption = $this->activeKey(Algorithms::ecdhEsA256Kw(), Keys::encryptionPair());

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('is not one it seals what leaves the process to');

        // When
        $this->provider->messageKey($this->tenant, $encryption->kid);
    }

    #[Test]
    public function theKeyMessagesAreSealedToIsNotAKeyAClientEncryptsTo(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('is one it keeps; it is not a key a client encrypts to');

        // When
        $this->provider->decryptionKey($this->tenant, $key->kid);
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function theKeyIsOpenedOnceAndKept(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());

        // When
        $first = $this->provider->messageKey($this->tenant, $key->kid);

        // Then
        static::assertSame($first, $this->provider->messageKey($this->tenant, $key->kid));
    }

    private function activeKey(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = $this->key($algorithm, $pair);
        $key->activate(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }

    private function key(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair, ?DateTimeImmutable $createdAt = null): TenantKey
    {
        $createdAt ??= Fixtures::now();
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            $createdAt,
            $createdAt,
        );
        $this->keys->save($key);

        return $key;
    }
}
