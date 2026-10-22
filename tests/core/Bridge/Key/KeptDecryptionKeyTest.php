<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Key;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\GeneratedKeyPair;
use Beffroi\Core\Domain\Key\KeyAlgorithmInterface;
use Beffroi\Core\Domain\Key\KeyUse;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\KeptEncryption;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

/**
 * Architecture §3.3, decisions 0018 and 0020, beffroi/saml S-64 and S-66: a key the tenant keeps out of its JWK Set
 * and is encrypted to, the key a SAML identity provider encrypts for, is answered to a caller that names its algorithm
 * and its "kid", opened by the KMS once per process, and never answered to a caller asking for another algorithm.
 */
final class KeptDecryptionKeyTest extends TestCase
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
     * A key in service of the algorithm asked, a staged one included, is opened: what was encrypted to it is opened.
     */
    #[Test]
    public function aKeyInServiceOfTheAlgorithmIsOpened(): void
    {
        // Given
        $key = $this->key(new KeptEncryption(), Keys::pair());

        // When
        $opened = $this->provider->keptDecryptionKey($this->tenant, new KeptEncryption(), $key->kid);

        // Then
        static::assertSame([$key, Keys::pair()->privateJwk], [$opened->key, $opened->privateJwk]);
    }

    /**
     * Decision 0018: the KMS is asked once per key and per process, never at every message opened.
     */
    #[Test]
    public function theKeyIsOpenedOncePerProcess(): void
    {
        // Given
        $key = $this->key(new KeptEncryption(), Keys::pair());
        $first = $this->provider->keptDecryptionKey($this->tenant, new KeptEncryption(), $key->kid);

        // When
        $second = $this->provider->keptDecryptionKey($this->tenant, new KeptEncryption(), $key->kid);

        // Then
        static::assertSame($first, $second);
    }

    /**
     * beffroi/saml S-64: the algorithm names whom a key belongs to, and the key of another holder is never answered,
     * whatever "kid" the caller names.
     */
    #[Test]
    public function theKeyOfAnotherAlgorithmIsNotAnswered(): void
    {
        // Given
        $key = $this->key(new KeptEncryption('b'), Keys::pair());

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs(sprintf('The key "%s" of tenant "acme" is a key of KEPT-ENCRYPTION:b, not of KEPT-ENCRYPTION:a.', $key->kid));

        // When
        $this->provider->keptDecryptionKey($this->tenant, new KeptEncryption('a'), $key->kid);
    }

    /**
     * A "kid" the tenant does not hold opens nothing.
     */
    #[Test]
    public function aKeyNobodyHoldsIsNotAnswered(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" holds no key "unknown".');

        // When
        $this->provider->keptDecryptionKey($this->tenant, new KeptEncryption(), 'unknown');
    }

    /**
     * A key that has retired is not opened any more, whatever was encrypted to it.
     */
    #[Test]
    public function aRetiredKeyIsNotAnswered(): void
    {
        // Given
        $key = $this->retired($this->key(new KeptEncryption(), Keys::pair()));

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs(sprintf('The key "%s" of tenant "acme" has retired: what was encrypted to it is not opened any more.', $key->kid));

        // When
        $this->provider->keptDecryptionKey($this->tenant, new KeptEncryption(), $key->kid);
    }

    /**
     * What the process held open of a key that has retired leaves it.
     */
    #[Test]
    public function aRetiredKeyLeavesTheProcess(): void
    {
        // Given
        $key = $this->key(new KeptEncryption(), Keys::pair());
        $opened = $this->provider->keptDecryptionKey($this->tenant, new KeptEncryption(), $key->kid);
        $this->retired($key);

        // When
        try {
            $this->provider->keptDecryptionKey($this->tenant, new KeptEncryption(), $key->kid);
        } catch (KeyNotFoundException) {
        }

        // Then
        static::assertNotSame($opened, $this->opened->open($this->tenant, $key));
    }

    /**
     * RFC 7517 §4.2: the use is asserted and not deduced from the caller, a key of another use opens nothing.
     */
    #[Test]
    public function aKeyOfAnotherUseIsNotAnswered(): void
    {
        // Given
        $key = $this->key(new KeptEncryption('a', KeyUse::Signature), Keys::pair());

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIsOrContains('"use": "sig"; it is not a key that opens');

        // When
        $this->provider->keptDecryptionKey($this->tenant, new KeptEncryption('a', KeyUse::Signature), $key->kid);
    }

    /**
     * The material of a pair of the suite under the algorithm a test names, its public JWK saying so, staged.
     */
    private function key(KeyAlgorithmInterface $algorithm, GeneratedKeyPair $pair): TenantKey
    {
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            $algorithm,
            [
                ...$pair->publicJwk,
                'alg' => $algorithm->name(),
                'use' => $algorithm->keyUse()->value,
            ],
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            Fixtures::now(),
            Fixtures::now(),
        );
        $this->keys->save($key);

        return $key;
    }

    private function retired(TenantKey $key): TenantKey
    {
        $key->activate(Fixtures::now());
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }
}
