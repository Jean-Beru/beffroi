<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\KeyManagement;

use Heidi\Core\Bridge\KeyManagement\EnvelopeKeySealer;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\KmsUnavailableException;
use Heidi\Core\Exception\RuntimeException;
use Heidi\Core\Tests\Fixture\EnvelopesThatThrow;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sodium_crypto_aead_xchacha20poly1305_ietf_keygen;
use function strlen;
use Symfony\Component\KeyManagement\EnvelopeEncrypter;
use Symfony\Component\KeyManagement\Exception\DecryptionFailedException;
use Symfony\Component\KeyManagement\Exception\RuntimeException as KeyManagementRuntimeException;
use Symfony\Component\KeyManagement\KeyLoader\InMemoryKeyLoader;
use Symfony\Component\KeyManagement\Local\SodiumKms;

final class EnvelopeKeySealerTest extends TestCase
{
    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * Architecture §3.3: the private key is stored sealed, exists in clear in memory only, and the KMS never
     * sees it (envelope mode wraps a data key).
     */
    #[Test]
    public function itSealsAPrivateJwkIntoOpaqueBytes(): void
    {
        // Given
        $private = Keys::pair()->privateJwk;

        // When
        $sealed = Keys::sealer()->seal($this->tenant, $private);

        // Then
        static::assertStringNotContainsString($private['d'], $sealed);
        static::assertStringNotContainsString($private['n'], $sealed);
    }

    #[Test]
    public function itOpensWhatItSealed(): void
    {
        // Given
        $private = Keys::pair()->privateJwk;
        $sealed = Keys::sealer()->seal($this->tenant, $private);

        // When
        $opened = Keys::sealer()->unseal($this->tenant, $sealed);

        // Then
        static::assertSame($private, $opened);
    }

    #[Test]
    public function twoSealsOfTheSameKeyDiffer(): void
    {
        // When / Then
        static::assertNotSame(Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk), Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk));
    }

    /**
     * The envelope is bound to its tenant: under the same KMS key, it does not open for another one.
     */
    #[Test]
    public function aKeySealedForOneTenantDoesNotOpenForAnother(): void
    {
        // Given
        $sealed = Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk);

        // Then
        $this->expectException(RuntimeException::class);

        // When
        Keys::sealer()->unseal(Fixtures::tenant('globex', 'https://id.globex.example'), $sealed);
    }

    /**
     * "{tenant}" in the KMS key identifier names one master key per tenant: the envelope of a tenant is
     * sealed under the key that carries its slug, and no other.
     */
    #[Test]
    public function theKmsKeyIsNamedFromTheTenant(): void
    {
        // Given
        $sealer = new EnvelopeKeySealer(new EnvelopeEncrypter(new SodiumKms(new InMemoryKeyLoader([
            'signing-keys-acme' => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
        ]))), 'signing-keys-{tenant}');

        // When
        $sealed = $sealer->seal($this->tenant, Keys::pair()->privateJwk);

        // Then
        static::assertSame(Keys::pair()->privateJwk, $sealer->unseal($this->tenant, $sealed));
    }

    /**
     * A KMS that holds no master key for the tenant serves nothing of it: an outage of the tenant, until an
     * operator gives the KMS its key, not a wrong input.
     */
    #[Test]
    public function aTenantWithoutItsKmsKeyCannotSeal(): void
    {
        // Given
        $sealer = new EnvelopeKeySealer(new EnvelopeEncrypter(new SodiumKms(new InMemoryKeyLoader([
            'signing-keys-acme' => sodium_crypto_aead_xchacha20poly1305_ietf_keygen(),
        ]))), 'signing-keys-{tenant}');

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs('The key of tenant "globex" could not be sealed under the KMS key "signing-keys-globex".');

        // When
        $sealer->seal(Fixtures::tenant('globex', 'https://id.globex.example'), Keys::pair()->privateJwk);
    }

    #[Test]
    public function itRefusesTamperedBytes(): void
    {
        // Given
        $tampered = Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk);
        $tampered[strlen($tampered) - 1] = $tampered[strlen($tampered) - 1] === 'a' ? 'b' : 'a';

        // Then
        $this->expectException(RuntimeException::class);

        // When
        Keys::sealer()->unseal($this->tenant, $tampered);
    }

    #[Test]
    public function itRefusesGarbage(): void
    {
        // Then
        $this->expectException(RuntimeException::class);

        // When
        Keys::sealer()->unseal($this->tenant, 'not an envelope');
    }

    /**
     * Issue #128: the same rule as for the secrets (KeyManagementFailure), a KMS that does not answer told
     * from an envelope it refuses.
     */
    #[Test]
    public function aKmsThatDoesNotAnswerAtOpeningIsAnOutage(): void
    {
        // Given
        $whatTheKmsThrew = new KeyManagementRuntimeException('Failed to reach Vault.');
        $sealer = new EnvelopeKeySealer(new EnvelopesThatThrow($whatTheKmsThrew), Keys::KMS_KEY_ID);

        // When
        try {
            $sealer->unseal($this->tenant, Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk));
            static::fail('The key should not have been opened.');
        } catch (KmsUnavailableException $exception) {
            // Then
            static::assertSame('The sealed key could not be opened.', $exception->getMessage());
            static::assertSame($whatTheKmsThrew, $exception->getPrevious());
        }
    }

    #[Test]
    public function aKmsThatDoesNotAnswerAtSealingIsAnOutage(): void
    {
        // Given
        $sealer = new EnvelopeKeySealer(new EnvelopesThatThrow(new KeyManagementRuntimeException('Failed to reach Vault.')), Keys::KMS_KEY_ID);

        // Then
        $this->expectException(KmsUnavailableException::class);
        $this->expectExceptionMessageIs('The key of tenant "acme" could not be sealed under the KMS key "signing-keys".');

        // When
        $sealer->seal($this->tenant, Keys::pair()->privateJwk);
    }

    #[Test]
    public function whatTheKmsRefusesAsAnEnvelopeIsNoOutage(): void
    {
        // Given
        $sealer = new EnvelopeKeySealer(new EnvelopesThatThrow(new DecryptionFailedException()), Keys::KMS_KEY_ID);

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIs('The sealed key could not be opened.');

        // When
        $sealer->unseal($this->tenant, Keys::sealer()->seal($this->tenant, Keys::pair()->privateJwk));
    }
}
