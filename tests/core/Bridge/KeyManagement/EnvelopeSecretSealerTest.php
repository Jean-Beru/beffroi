<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\KeyManagement;

use Heidi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\RuntimeException;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Core\Tests\Fixture\Totps;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sodium_crypto_aead_xchacha20poly1305_ietf_keygen;
use Symfony\Component\KeyManagement\Envelope;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\KeyLoader\InMemoryKeyLoader;
use Symfony\Component\KeyManagement\Local\SodiumKms;

/**
 * Architecture §3.3: the shared secrets of the users sealed under the KMS of the tenant like the signing
 * keys, in an envelope of their own use.
 */
final class EnvelopeSecretSealerTest extends TestCase
{
    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    #[Test]
    public function itSealsASecretIntoAnEnvelopeThatCarriesNothingOfIt(): void
    {
        // When
        $sealed = Totps::sealer()->seal($this->tenant, Totps::SEED);

        // Then
        static::assertStringNotContainsString(Totps::SEED, $sealed);
        static::assertStringNotContainsString(Base32::encodeUpperUnpadded(Totps::SEED), $sealed);
        static::assertSame(Keys::KMS_KEY_ID, Envelope::fromBytes($sealed)->keyId);
    }

    #[Test]
    public function itOpensWhatItSealed(): void
    {
        // Given
        $sealed = Totps::sealer()->seal($this->tenant, Totps::SEED);

        // When / Then
        static::assertSame(Totps::SEED, Totps::sealer()->unseal($this->tenant, $sealed));
    }

    #[Test]
    public function twoSealsOfTheSameSecretDiffer(): void
    {
        // When / Then
        static::assertNotSame(Totps::sealer()->seal($this->tenant, Totps::SEED), Totps::sealer()->seal($this->tenant, Totps::SEED));
    }

    /**
     * The envelope is bound to its tenant: under the same KMS key, it does not open for another one.
     */
    #[Test]
    public function aSecretSealedForOneTenantDoesNotOpenForAnother(): void
    {
        // Given
        $sealed = Totps::sealer()->seal($this->tenant, Totps::SEED);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The sealed secret could not be opened.');

        // When
        Totps::sealer()->unseal(Fixtures::tenant('globex', 'https://id.globex.example'), $sealed);
    }

    /**
     * The envelope is bound to its use: under the same KMS key and for the same tenant, the envelope of a
     * signing key is not a secret, and a secret is not a signing key.
     */
    #[Test]
    public function theEnvelopeOfASigningKeyDoesNotOpenAsASecret(): void
    {
        // Given
        $sealedKey = Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk);

        // Then
        $this->expectException(RuntimeException::class);

        // When
        Totps::sealer()->unseal($this->tenant, $sealedKey);
    }

    /**
     * The use is in the authenticated data, not the tenant alone: an envelope bound to the slug only,
     * whatever wrote it, is not a secret of the provider.
     */
    #[Test]
    public function anEnvelopeBoundToTheTenantAloneDoesNotOpenAsASecret(): void
    {
        // Given
        $sealed = (string) Keys::envelopes()->encrypt(Keys::KMS_KEY_ID, Totps::SEED, $this->tenant->slug);

        // Then
        $this->expectException(RuntimeException::class);

        // When
        Totps::sealer()->unseal($this->tenant, $sealed);
    }

    #[Test]
    public function theEnvelopeOfASecretDoesNotOpenAsASigningKey(): void
    {
        // Given
        $sealedSecret = Totps::sealer()->seal($this->tenant, Totps::SEED);

        // Then
        $this->expectException(RuntimeException::class);

        // When
        Keys::sealer()->unseal($this->tenant, $sealedSecret);
    }

    /**
     * "{tenant}" in the KMS key identifier names one master key per tenant, as for the signing keys.
     */
    #[Test]
    public function theKmsKeyIsNamedFromTheTenant(): void
    {
        // Given
        $sealer = new EnvelopeSecretSealer(new EnvelopeEncrypter(new SodiumKms(new InMemoryKeyLoader([
            'secrets-acme' => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
        ]))), 'secrets-{tenant}');

        // When
        $sealed = $sealer->seal($this->tenant, Totps::SEED);

        // Then
        static::assertSame('secrets-acme', Envelope::fromBytes($sealed)->keyId);
        static::assertSame(Totps::SEED, $sealer->unseal($this->tenant, $sealed));
    }

    #[Test]
    public function aTenantWithoutItsKmsKeyCannotSeal(): void
    {
        // Given
        $sealer = new EnvelopeSecretSealer(new EnvelopeEncrypter(new SodiumKms(new InMemoryKeyLoader([
            'secrets-acme' => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
        ]))), 'secrets-{tenant}');

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('A secret of tenant "globex" could not be sealed under the KMS key "secrets-globex".');

        // When
        $sealer->seal(Fixtures::tenant('globex', 'https://id.globex.example'), Totps::SEED);
    }

    #[Test]
    public function itRefusesGarbage(): void
    {
        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The sealed secret could not be opened.');

        // When
        Totps::sealer()->unseal($this->tenant, 'not an envelope');
    }
}
