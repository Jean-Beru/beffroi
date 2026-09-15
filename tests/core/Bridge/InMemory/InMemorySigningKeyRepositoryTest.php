<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\InMemory;

use Heidi\Core\Bridge\InMemory\InMemorySigningKeyRepository;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class InMemorySigningKeyRepositoryTest extends TestCase
{
    private Tenant $acme;

    private Tenant $other;

    private InMemorySigningKeyRepository $repository;

    private SigningKey $otherKey;

    protected function setUp(): void
    {
        $this->acme = Fixtures::tenant();
        $this->other = Fixtures::tenant('other', 'https://id.other.example');
        $this->repository = new InMemorySigningKeyRepository();
        $this->otherKey = new SigningKey(Keys::pair()->kid, $this->other, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now());
        $this->repository->save($this->otherKey);
    }

    #[Test]
    public function aTenantWithoutKeysHasNoActiveKey(): void
    {
        // When / Then
        static::assertNull($this->repository->findActive($this->acme, SignatureAlgorithm::RS256));
    }

    #[Test]
    public function aTenantWithoutKeysPublishesNothing(): void
    {
        // When / Then
        static::assertSame([], $this->repository->findPublished($this->acme));
    }

    #[Test]
    public function keysAreScopedByTenantEvenWithTheSameKid(): void
    {
        // Given
        $acmeKey = new SigningKey(Keys::pair()->kid, $this->acme, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now());
        $this->repository->save($acmeKey);

        // When / Then
        static::assertSame($acmeKey, $this->repository->find($this->acme, Keys::pair()->kid));
        static::assertSame($this->otherKey, $this->repository->find($this->other, Keys::pair()->kid));
    }

    #[Test]
    public function anActiveKeyIsFoundActiveAndPublished(): void
    {
        // Given
        $acmeKey = new SigningKey(Keys::pair()->kid, $this->acme, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now());
        $this->repository->save($acmeKey);

        // When / Then
        static::assertSame($acmeKey, $this->repository->findActive($this->acme, SignatureAlgorithm::RS256));
        static::assertSame([$acmeKey], $this->repository->findPublished($this->acme));
    }

    #[Test]
    public function anUnknownKidIsNotFound(): void
    {
        // When / Then
        static::assertNull($this->repository->find($this->acme, 'unknown'));
    }

    #[Test]
    public function aRetiringKeyIsPublishedButNotActive(): void
    {
        // Given
        $key = new SigningKey(Keys::pair()->kid, $this->acme, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now());
        $key->startRetiring(Fixtures::now());
        $this->repository->save($key);

        // When / Then
        static::assertNull($this->repository->findActive($this->acme, SignatureAlgorithm::RS256));
        static::assertSame([$key], $this->repository->findPublished($this->acme));
    }
}
