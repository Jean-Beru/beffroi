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
 * Architecture §3.3, Decisions 0018 and 0020, beffroi/saml S-64 and S-66
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

    #[Test]
    public function aKeyInServiceOfTheAlgorithmIsOpened(): void
    {
        // Given
        $key = $this->key(new KeptEncryption(), Keys::pair());

        // When
        $opened = $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), [$key->kid]);

        // Then
        static::assertSame([[$key, Keys::pair()->privateJwk]], [[$opened[0]->key, $opened[0]->privateJwk]]);
    }

    /**
     * Decision 0018
     */
    #[Test]
    public function theKeyIsOpenedOncePerProcess(): void
    {
        // Given
        $key = $this->key(new KeptEncryption(), Keys::pair());
        $first = $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), [$key->kid]);

        // When
        $second = $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), [$key->kid]);

        // Then
        static::assertSame($first[0], $second[0]);
    }

    /**
     * beffroi/saml S-64
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
        $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption('a'), [$key->kid]);
    }

    #[Test]
    public function aKeyNobodyHoldsIsNotAnswered(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" holds no key "unknown".');

        // When
        $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), ['unknown']);
    }

    #[Test]
    public function aRetiredKeyIsNotAnswered(): void
    {
        // Given
        $key = $this->retired($this->key(new KeptEncryption(), Keys::pair()));

        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs(sprintf('The key "%s" of tenant "acme" has retired: what was encrypted to it is not opened any more.', $key->kid));

        // When
        $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), [$key->kid]);
    }

    #[Test]
    public function aRetiredKeyLeavesTheProcess(): void
    {
        // Given
        $key = $this->key(new KeptEncryption(), Keys::pair());
        $opened = $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), [$key->kid])[0];
        $this->retired($key);

        // When
        try {
            $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), [$key->kid]);
        } catch (KeyNotFoundException) {
        }

        // Then
        static::assertNotSame($opened, $this->opened->open($this->tenant, $key));
    }

    #[Test]
    public function theKeysAreAnsweredInTheOrderNamed(): void
    {
        // Given
        $first = $this->key(new KeptEncryption(), Keys::pair());
        $second = $this->key(new KeptEncryption(), Keys::otherPair());

        // When
        $opened = $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), [$second->kid, $first->kid]);

        // Then
        static::assertSame([$second, $first], [$opened[0]->key, $opened[1]->key]);
    }

    #[Test]
    public function aKeyNoLongerNamedLeavesTheProcess(): void
    {
        // Given
        $previous = $this->key(new KeptEncryption(), Keys::pair());
        $next = $this->key(new KeptEncryption(), Keys::otherPair());
        $opened = $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), [$next->kid, $previous->kid]);

        // When
        $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption(), [$next->kid]);

        // Then
        static::assertSame([false, true], [
            $opened[1] === $this->opened->open($this->tenant, $previous),
            $opened[0] === $this->opened->open($this->tenant, $next),
        ]);
    }

    #[Test]
    public function theKeysOfAnotherAlgorithmStayOpen(): void
    {
        // Given
        $elsewhere = $this->key(new KeptEncryption('b'), Keys::pair());
        $opened = $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption('b'), [$elsewhere->kid])[0];

        // When
        $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption('a'), []);

        // Then
        static::assertSame($opened, $this->opened->open($this->tenant, $elsewhere));
    }

    /**
     * RFC 7517 §4.2
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
        $this->provider->keptDecryptionKeys($this->tenant, new KeptEncryption('a', KeyUse::Signature), [$key->kid]);
    }

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
