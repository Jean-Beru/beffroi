<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\KeyManagement;

use Beffroi\Core\Bridge\KeyManagement\EnvelopeSecretSealer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\EnvelopesThatThrow;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Core\Tests\Fixture\Totps;
use JsonException;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sodium_crypto_aead_xchacha20poly1305_ietf_keygen;
use Symfony\Component\KeyManagement\Envelope;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\Exception\DataKeyNotFoundException;
use Symfony\Component\KeyManagement\Exception\DecryptionFailedException;
use Symfony\Component\KeyManagement\Exception\KeyNotFoundException;
use Symfony\Component\KeyManagement\Exception\LogicException as KeyManagementLogicException;
use Symfony\Component\KeyManagement\Exception\RuntimeException as KeyManagementRuntimeException;
use Symfony\Component\KeyManagement\Exception\UnsupportedOperationException;
use Symfony\Component\KeyManagement\KeyLoader\InMemoryKeyLoader;
use Symfony\Component\KeyManagement\Local\SodiumKms;
use Throwable;

/**
 * Architecture §3.3
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

    #[Test]
    public function theEnvelopeOfATenantKeyDoesNotOpenAsASecret(): void
    {
        // Given
        $sealedKey = Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk);

        // Then
        $this->expectException(RuntimeException::class);

        // When
        Totps::sealer()->unseal($this->tenant, $sealedKey);
    }

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
    public function aSecretSealedForOnePurposeDoesNotOpenForAnother(): void
    {
        // Given
        $sealed = new EnvelopeSecretSealer(Keys::envelopes(), Keys::KMS_KEY_ID, 'beffroi:access-token-person:v1:')->seal($this->tenant, Totps::SEED);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The sealed secret could not be opened.');

        // When
        new EnvelopeSecretSealer(Keys::envelopes(), Keys::KMS_KEY_ID)->unseal($this->tenant, $sealed);
    }

    #[Test]
    public function aSecretSealedForAPurposeOpensForThatPurpose(): void
    {
        // Given
        $sealer = new EnvelopeSecretSealer(Keys::envelopes(), Keys::KMS_KEY_ID, 'beffroi:access-token-person:v1:');

        // When / Then
        static::assertSame(Totps::SEED, $sealer->unseal($this->tenant, $sealer->seal($this->tenant, Totps::SEED)));
    }

    #[Test]
    public function theEnvelopeOfASecretDoesNotOpenAsATenantKey(): void
    {
        // Given
        $sealedSecret = Totps::sealer()->seal($this->tenant, Totps::SEED);

        // Then
        $this->expectException(RuntimeException::class);

        // When
        Keys::sealer()->unseal($this->tenant, $sealedSecret);
    }

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
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs('The secret of tenant "globex" could not be sealed under the KMS key "secrets-globex".');

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

    #[Test]
    #[DataProvider('provideOutagesOfTheKms')]
    public function aKmsThatDoesNotAnswerAtOpeningIsAnOutage(Throwable $whatTheKmsThrew): void
    {
        // Given
        $sealer = new EnvelopeSecretSealer(new EnvelopesThatThrow($whatTheKmsThrew), Keys::KMS_KEY_ID);

        // When
        try {
            $sealer->unseal($this->tenant, Totps::sealer()->seal($this->tenant, Totps::SEED));
            static::fail('The secret should not have been opened.');
        } catch (KmsUnavailableException $exception) {
            // Then
            static::assertSame('The sealed secret could not be opened.', $exception->getMessage());
            static::assertSame($whatTheKmsThrew, $exception->getPrevious());
        }
    }

    /**
     * @return iterable<string, array{Throwable}>
     */
    public static function provideOutagesOfTheKms(): iterable
    {
        yield 'the KMS cannot be reached' => [new KeyManagementRuntimeException('Failed to reach Vault.')];
        yield 'the KMS answers an error' => [new KeyManagementRuntimeException('Vault request failed (HTTP 503): "Vault is sealed".')];
        yield 'the KMS does not hold the master key' => [new KeyNotFoundException('signing-keys')];
    }

    #[Test]
    public function aKmsThatDoesNotAnswerAtSealingIsAnOutage(): void
    {
        // Given
        $whatTheKmsThrew = new KeyManagementRuntimeException('Failed to reach Vault.');
        $sealer = new EnvelopeSecretSealer(new EnvelopesThatThrow($whatTheKmsThrew), Keys::KMS_KEY_ID);

        // When
        try {
            $sealer->seal($this->tenant, Totps::SEED);
            static::fail('The secret should not have been sealed.');
        } catch (KmsUnavailableException $exception) {
            // Then
            static::assertSame('The secret of tenant "acme" could not be sealed under the KMS key "signing-keys".', $exception->getMessage());
            static::assertSame($whatTheKmsThrew, $exception->getPrevious());
        }
    }

    #[Test]
    #[DataProvider('provideRefusalsThatAreNoOutage')]
    public function whatTheKmsRefusesAsAnEnvelopeIsNoOutage(Throwable $whatTheKmsThrew): void
    {
        // Given
        $sealer = new EnvelopeSecretSealer(new EnvelopesThatThrow($whatTheKmsThrew), Keys::KMS_KEY_ID);

        // When
        try {
            $sealer->unseal($this->tenant, Totps::sealer()->seal($this->tenant, Totps::SEED));
            static::fail('The secret should not have been opened.');
        } catch (RuntimeException $exception) {
            // Then
            static::assertSame('The sealed secret could not be opened.', $exception->getMessage());
            static::assertSame($whatTheKmsThrew, $exception->getPrevious());
        }
    }

    /**
     * @return iterable<string, array{Throwable}>
     */
    public static function provideRefusalsThatAreNoOutage(): iterable
    {
        yield 'an envelope invalid, tampered, foreign, or under a key the KMS does not know' => [new DecryptionFailedException()];
        yield 'a stored data key the store no longer holds' => [new DataKeyNotFoundException('reference')];
        yield 'what the backend cannot do by configuration' =>
            [new UnsupportedOperationException('Vault Transit silently ignores the context parameter on non-derived keys.')];
        yield 'a format the decrypter cannot resolve' => [new KeyManagementLogicException('The envelope refers to a stored data key.')];
        yield 'a failure that is not the component\'s' => [new JsonException('Syntax error')];
    }
}
