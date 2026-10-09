<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Key;

use function array_map;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
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
 * Decision 0020, architecture §3.3: the key a tenant seals what leaves the process to is a key of the
 * tenant in every way but one, and that one is that its issuer never publishes it. A key in the JWK Set
 * would make a message body forgeable by any reader of the discovery document.
 */
final class MessageKeyTest extends TestCase
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
     * RFC 7517 §5: the JWK Set is what the tenant answers to whoever reads its issuer, and nothing a
     * message body is sealed to is addressed to such a reader.
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

    /**
     * What seals is the active key of that algorithm, and asking for it asks the KMS nothing: what is
     * answered is the key with its public half in the clear and its private half still sealed.
     */
    #[Test]
    public function theActiveKeyIsWhatSealsAndItsPrivateHalfStaysSealed(): void
    {
        // Given
        $key = $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());

        // When
        $sealing = $this->provider->activeMessageKey($this->tenant, Algorithms::messageSeal());

        // Then
        static::assertSame($key, $sealing);
        static::assertSame(Keys::messagePair()->publicJwk, $sealing->publicJwk);
    }

    /**
     * A tenant whose keys have not been generated seals nothing, and is told so: a body is not written at
     * all rather than written in the clear.
     */
    #[Test]
    public function aTenantWithNoActiveKeySealsNothing(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" has no active MESSAGE-SEAL key: nothing it writes to a transport can be sealed.');

        // When
        $this->provider->activeMessageKey($this->tenant, Algorithms::messageSeal());
    }

    /**
     * A retirement is what bounds how long a body of that vintage may wait: past it, the key opens
     * nothing, as it does for a key a client encrypted to.
     */
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

    /**
     * The family is asserted and not deduced from the caller: the key a client encrypts to never opens a
     * message of this provider, whoever asks for it under that name.
     */
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

    /**
     * And the other way round: a client that named the "kid" of the key this tenant keeps is answered that
     * the tenant publishes nothing of the sort, rather than handed it.
     */
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
     * Decision 0018: the KMS is asked once for a key and the private half stays on the thread that opened
     * it, which is what makes a worker pay one opening for every message of that vintage.
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
