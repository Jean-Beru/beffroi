<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Doctrine\PersonalData;

use Beffroi\Bundle\Doctrine\PersonalData\TenantScopedEncrypter;
use Beffroi\Bundle\Tests\Fixture\AmbientTenant;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\KeyManagement\Envelope;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\Exception\DecryptionFailedException;
use Symfony\Component\KeyManagement\StoredEnvelopeEncrypter;
use Symfony\Component\KeyManagement\Test\InMemoryDataKeyStore;
use Symfony\Component\KeyManagement\Test\InMemoryKms;

/**
 * Decision 0018: the scope of a sealed column carries the tenant, the envelope is bound to it, and a write
 * with no ambient tenant is refused rather than falling back on a scope of its own.
 */
final class TenantScopedEncrypterTest extends TestCase
{
    private const string FAMILY = 'user';

    /**
     * The scope the store sees is the family prefixed by the slug of the ambient tenant, which is the only
     * channel there is between an encrypted type and the store.
     */
    #[Test]
    public function theScopeTheStoreSeesCarriesTheSlugOfTheAmbientTenant(): void
    {
        // Given
        $store = new InMemoryDataKeyStore();
        $encrypter = new TenantScopedEncrypter(new StoredEnvelopeEncrypter($store), new AmbientTenant(Fixtures::tenant('acme')));

        // When
        $encrypter->encrypt(self::FAMILY, 'alice@example.com');

        // Then
        $scopes = [];
        foreach ($store->all() as $key) {
            $scopes[] = $key->scope;
        }
        static::assertSame(['acme.user'], $scopes);
    }

    /**
     * Decision 0011 refuses a data key shared between two tenants, and the store returns the newest key of
     * a scope without reading any other column: two tenants sealing the same value in the same column are
     * two keys and two ciphertexts.
     */
    #[Test]
    public function twoTenantsSealingTheSameValueInTheSameColumnDoNotShareAKey(): void
    {
        // Given
        $store = new InMemoryDataKeyStore();
        $envelopes = new StoredEnvelopeEncrypter($store);
        $acme = new TenantScopedEncrypter($envelopes, new AmbientTenant(Fixtures::tenant('acme')));
        $globex = new TenantScopedEncrypter($envelopes, new AmbientTenant(Fixtures::tenant('globex')));

        // When
        $ofAcme = $acme->encrypt(self::FAMILY, 'alice@example.com');
        $ofGlobex = $globex->encrypt(self::FAMILY, 'alice@example.com');

        // Then
        static::assertNotSame((string) $ofAcme, (string) $ofGlobex);
        static::assertNotSame($ofAcme->reference, $ofGlobex->reference);
        static::assertSame('alice@example.com', $acme->decrypt($ofAcme));
        static::assertSame('alice@example.com', $globex->decrypt($ofGlobex));
    }

    /**
     * The authenticated data of the envelope name the tenant, as `TenantEnvelope` names them for a signing
     * key and for a sealed secret: a ciphertext of one tenant does not open for another, whatever row it is
     * found in.
     */
    #[Test]
    public function aValueSealedForOneTenantDoesNotOpenForAnother(): void
    {
        // Given
        $store = new InMemoryDataKeyStore();
        $envelopes = new StoredEnvelopeEncrypter($store);
        $acme = new TenantScopedEncrypter($envelopes, new AmbientTenant(Fixtures::tenant('acme')));
        $globex = new TenantScopedEncrypter($envelopes, new AmbientTenant(Fixtures::tenant('globex')));
        $sealed = $acme->encrypt(self::FAMILY, 'alice@example.com');

        // Then
        $this->expectException(DecryptionFailedException::class);

        // When
        $globex->decrypt($sealed);
    }

    /**
     * A value sealed outside the scope of its tenant is a value no destruction of that tenant's keys
     * reaches, so a write that cannot name a tenant refuses and the refusal names the family.
     */
    #[Test]
    public function aWriteWithNoAmbientTenantIsRefusedAndNamesTheFamily(): void
    {
        // Given
        $encrypter = new TenantScopedEncrypter(new StoredEnvelopeEncrypter(new InMemoryDataKeyStore()), new AmbientTenant(null));

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIsOrContains('a column of the "user" family cannot be sealed');

        // When
        $encrypter->encrypt(self::FAMILY, 'alice@example.com');
    }

    /**
     * Nothing is written when the tenant cannot be named: the refusal happens before the store is asked
     * for a key, so no scope of a tenant nobody named is created either.
     */
    #[Test]
    public function aWriteWithNoAmbientTenantMintsNoDataKey(): void
    {
        // Given
        $store = new InMemoryDataKeyStore();
        $encrypter = new TenantScopedEncrypter(new StoredEnvelopeEncrypter($store), new AmbientTenant(null));

        // When
        try {
            $encrypter->encrypt(self::FAMILY, 'alice@example.com');
        } catch (RuntimeException) {
        }

        // Then
        static::assertSame([], iterator_to_array($store->all()));
    }

    /**
     * A read is refused the same way: the tenant is what the authenticated data name, so a read that
     * cannot name one has nothing to open the envelope with.
     */
    #[Test]
    public function aReadWithNoAmbientTenantIsRefused(): void
    {
        // Given
        $store = new InMemoryDataKeyStore();
        $envelopes = new StoredEnvelopeEncrypter($store);
        $sealed = new TenantScopedEncrypter($envelopes, new AmbientTenant(Fixtures::tenant('acme')))->encrypt(self::FAMILY, 'alice@example.com');
        $encrypter = new TenantScopedEncrypter($envelopes, new AmbientTenant(null));

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIsOrContains('a sealed value cannot be read');

        // When
        $encrypter->decrypt($sealed);
    }

    /**
     * An envelope that carries its own data key is read through the fallback rather than refused: nothing
     * of this repository has written one into a column, but the sealed keys and the sealed secrets are
     * envelopes of that shape and the same encrypter is what reads them.
     */
    #[Test]
    public function aSelfContainedEnvelopeIsReadThroughTheFallback(): void
    {
        // Given
        $kms = new InMemoryKms();
        $tenant = Fixtures::tenant('acme');
        $selfContained = new EnvelopeEncrypter($kms);
        $envelope = $selfContained->encrypt('beffroi-acme', 'alice@example.com', TenantScopedEncrypter::AAD . 'acme');
        $encrypter = new TenantScopedEncrypter(
            new StoredEnvelopeEncrypter(new InMemoryDataKeyStore(['default' => $kms]), $selfContained),
            new AmbientTenant($tenant),
        );

        // When
        $read = $encrypter->decrypt(Envelope::fromBytes((string) $envelope));

        // Then
        static::assertSame('alice@example.com', $read);
    }

    /**
     * The slug of a scope is what precedes the first separator, which is what routes a write to the store
     * of its tenant; a slug carries no separator of its own, being lowercase letters, digits and hyphens.
     */
    #[Test]
    #[DataProvider('provideScopes')]
    public function theSlugOfAScopeIsWhatPrecedesTheFirstSeparator(string $scope, string $expected): void
    {
        // When / Then
        static::assertSame($expected, TenantScopedEncrypter::slugOf($scope));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideScopes(): iterable
    {
        yield 'a family of the spike' => ['acme.user', 'acme'];
        yield 'a family whose name is a sentence' => ['acme.backchannel_authentication_request', 'acme'];
        yield 'a slug with a hyphen' => ['acme-europe.user', 'acme-europe'];
        yield 'a scope nothing composed' => ['acme', 'acme'];
    }
}
