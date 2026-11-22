<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Bridge\Model;

use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Saml\Bridge\Pki\SelfSignedCertificateIssuer;
use Beffroi\Saml\Tests\Fixture\SamlKeys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * spec/saml.md S-15, S-37
 */
final class TenantSigningTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryTenantKeyRepository $keys;

    private TenantKey $key;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant('acme', 'https://id.acme.example');
        $this->keys = new InMemoryTenantKeyRepository();
        $this->key = SamlKeys::activeKey($this->tenant);
        $this->keys->save($this->key);
    }

    /**
     * S-37
     */
    #[Test]
    public function itCarriesTheCertificateOfTheActiveKey(): void
    {
        // When
        $signing = SamlKeys::signing($this->keys)->of($this->tenant);

        // Then
        static::assertSame(new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key))->pem(), $signing->certificatePem);
    }

    /**
     * S-2, S-37
     */
    #[Test]
    public function theCertificateOfAStagedKeyIsNotCarried(): void
    {
        // Given
        $this->keys->save(SamlKeys::key($this->tenant, SamlKeys::otherPair(), Fixtures::now()->modify('+1 day')));

        // When
        $signing = SamlKeys::signing($this->keys)->of($this->tenant);

        // Then
        static::assertSame(new SelfSignedCertificateIssuer()->selfSigned(SamlKeys::opened($this->key))->pem(), $signing->certificatePem);
    }
}
