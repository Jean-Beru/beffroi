<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Doctrine\PersonalData;

use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Tests\Symfony\Fixture\AmbientTenant;
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
 * Decision 0018
 */
final class TenantScopedEncrypterTest extends TestCase
{
    private const string FAMILY = 'user';

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
     * Decision 0011
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
