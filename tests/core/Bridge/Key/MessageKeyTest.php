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
 * Decision 0020, architecture §3.3: the key a tenant seals what leaves the process to is a key of the
 * tenant in every way but one, and that one is that its issuer never publishes it. A key in the JWK Set
 * would make a message body forgeable by any reader of the discovery document.
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
     * What seals is the key of that algorithm, and asking for it asks the KMS nothing: what is answered is
     * the key with its public half in the clear and its private half still sealed.
     */
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

    /**
     * Issue #548: a rotation saves the new key and then announces it, so the key a body is sealed to is the
     * newest in service and never the active one. A key that could only be sealed to once active could not
     * seal the event that announces it, and no tenant could be given a first one.
     */
    #[Test]
    public function aKeyThatIsStillStagedIsWhatSeals(): void
    {
        // Given
        $staged = $this->key(Algorithms::messageSeal(), Keys::messagePair());

        // When / Then
        static::assertSame($staged, $this->provider->sealingKey($this->tenant, Algorithms::messageSeal()));
    }

    /**
     * And the successor of a rotation takes the sealing over from the key that is active, the staging
     * window of such a key having nobody to wait for.
     */
    #[Test]
    public function aSuccessorStagedForTheKeyTakesTheSealingOver(): void
    {
        // Given
        $this->activeKey(Algorithms::messageSeal(), Keys::messagePair());
        $successor = $this->key(Algorithms::messageSeal(), Keys::otherMessagePair(), Fixtures::now()->modify('+90 days'));

        // When / Then
        static::assertSame($successor, $this->provider->sealingKey($this->tenant, Algorithms::messageSeal()));
    }

    /**
     * A key that has retired seals nothing, and a tenant left with only that one is a tenant that writes
     * nothing to a transport.
     */
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

    /**
     * A tenant whose keys have not been generated seals nothing, and is told which key comes first: a body
     * is not written at all rather than written in the clear.
     */
    #[Test]
    public function aTenantWithNoKeySealsNothingAndIsToldWhichComesFirst(): void
    {
        // Then
        $this->expectException(KeyNotFoundException::class);
        $this->expectExceptionMessageIs('Tenant "acme" holds no MESSAGE-SEAL key: it is the first key a tenant is given, and nothing it writes to a transport leaves the process before it exists.');

        // When
        $this->provider->sealingKey($this->tenant, Algorithms::messageSeal());
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
     * And what the process had open of that key goes with the refusal: a private half that opens nothing
     * any more has no reason to stay, so asking for it again is asking the KMS again.
     */
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
        $key = $this->key($algorithm, $pair);
        $key->activate(Fixtures::now());
        $this->keys->save($key);

        return $key;
    }

    /**
     * A key saved and left staged, as a rotation leaves it between the moment it is written and the moment
     * it takes over.
     */
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
