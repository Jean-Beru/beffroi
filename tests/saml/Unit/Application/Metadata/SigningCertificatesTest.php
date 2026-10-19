<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Application\Metadata;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\OpenedKeys;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Port\KeySealerInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use Beffroi\Saml\Application\Metadata\SigningCertificates;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Tests\Fixture\CountingKeySealer;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use function array_map;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md section 6.1 step 2, S-1, S-2, S-3: the certificate of each SAML key of a tenant in service, in creation
 * order, each key opened by the KMS once per process.
 */
final class SigningCertificatesTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->keys = new InMemoryTenantKeyRepository();
    }

    /**
     * S-2: the staged key, which signs nothing yet, has its certificate beside the active one's, in creation order.
     */
    #[Test]
    public function theNextCertificateIsListedBesideTheCurrentOne(): void
    {
        // Given
        $active = SamlKeys::activeKey($this->tenant);
        $staged = SamlKeys::key($this->tenant, SamlKeys::otherPair(), Fixtures::now()->modify('+1 day'));
        $this->keys->save($staged);
        $this->keys->save($active);

        // When
        $certificates = $this->certificates()->of($this->tenant);

        // Then
        static::assertSame($this->base64Of([$active, $staged]), self::base64($certificates));
    }

    /**
     * S-2: a key that has retired is out of the metadata.
     */
    #[Test]
    public function aRetiredKeyIsNotListed(): void
    {
        // Given
        $retired = SamlKeys::activeKey($this->tenant);
        $retired->startRetiring(Fixtures::now(), Fixtures::now());
        $retired->retire(Fixtures::now());
        $this->keys->save($retired);
        $active = SamlKeys::activeKey($this->tenant, SamlKeys::otherPair(), Fixtures::now()->modify('+1 day'));
        $this->keys->save($active);

        // When
        $certificates = $this->certificates()->of($this->tenant);

        // Then
        static::assertSame($this->base64Of([$active]), self::base64($certificates));
    }

    /**
     * Section 6.1 step 1, S-1: a key of any other algorithm of the tenant has no certificate in the metadata.
     */
    #[Test]
    public function aKeyOfAnotherAlgorithmIsNotListed(): void
    {
        // Given
        $this->keys->save(SamlKeys::key($this->tenant, Keys::pair(), algorithm: Algorithms::rs256()));

        // When
        $certificates = $this->certificates()->of($this->tenant);

        // Then
        static::assertSame([], $certificates);
    }

    /**
     * Section 6.1 step 2, S-3: a key is opened by the KMS once per process, whatever the number of times the metadata
     * is asked for.
     */
    #[Test]
    public function aKeyIsOpenedOncePerProcess(): void
    {
        // Given
        $key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($key);
        $sealer = self::createMock(KeySealerInterface::class);
        $sealer->expects(static::once())->method('unseal')->willReturn(SamlKeys::pair()->privateJwk);
        $certificates = new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer());
        $certificates->of($this->tenant);

        // When
        $again = $certificates->of($this->tenant);

        // Then
        static::assertSame($this->base64Of([$key]), self::base64($again));
    }

    /**
     * S-1: what is kept of a key that has left service is forgotten with it, so that a key under that name in service
     * again is opened again rather than answered from memory.
     */
    #[Test]
    public function theCertificateOfAKeyThatLeftServiceIsForgotten(): void
    {
        // Given
        $sealer = self::createMock(KeySealerInterface::class);
        $sealer->expects(static::exactly(2))->method('unseal')->willReturn(SamlKeys::pair()->privateJwk);
        $certificates = new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer());
        $key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($key);
        $certificates->of($this->tenant);
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $certificates->of($this->tenant);
        $this->keys->save(SamlKeys::activeKey($this->tenant));

        // When
        $listed = $certificates->of($this->tenant);

        // Then
        static::assertSame($this->base64Of([$key]), self::base64($listed));
    }

    /**
     * S-1: forgetting the keys of one tenant leaves what was built for another as it was.
     */
    #[Test]
    public function forgettingTheKeysOfOneTenantLeavesAnotherOnesAlone(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->keys->save(SamlKeys::activeKey($other));
        $sealer = self::createMock(KeySealerInterface::class);
        $sealer->expects(static::once())->method('unseal')->willReturn(SamlKeys::pair()->privateJwk);
        $certificates = new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer());
        $certificates->of($other);

        // When
        $certificates->of($this->tenant);

        // Then
        static::assertCount(1, $certificates->of($other));
    }

    /**
     * S-1, S-3: the private half opened to build a certificate is dropped at once, the active key's as any other, so
     * that the memory of the core holds nothing once the metadata is served: the first signature of the process opens
     * the active key for itself.
     */
    #[Test]
    public function theCertificatesLeaveNoPrivateHalfOpen(): void
    {
        // Given
        $this->keys->save(SamlKeys::activeKey($this->tenant));
        $sealer = new CountingKeySealer();
        $signingKeys = new SealedKeyProvider($this->keys, new OpenedKeys($sealer));
        new SigningCertificates($this->keys, $sealer, new SelfSignedCertificateIssuer())->of($this->tenant);

        // When
        $signingKeys->activeKeptSigningKey($this->tenant, SamlKeys::algorithm());

        // Then
        static::assertSame(2, $sealer->unsealed);
    }

    private function certificates(): SigningCertificates
    {
        return new SigningCertificates($this->keys, Keys::sealer(), new SelfSignedCertificateIssuer());
    }

    /**
     * @param list<TenantKey> $keys
     *
     * @return list<string>
     */
    private function base64Of(array $keys): array
    {
        $issuer = new SelfSignedCertificateIssuer();

        return array_map(
            static fn (TenantKey $key): string => $issuer->selfSigned(SamlKeys::opened($key))->base64,
            $keys,
        );
    }

    /**
     * @param list<Certificate> $certificates
     *
     * @return list<string>
     */
    private static function base64(array $certificates): array
    {
        return array_map(static fn (Certificate $certificate): string => $certificate->base64, $certificates);
    }
}
