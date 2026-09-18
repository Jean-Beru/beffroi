<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\InMemory;

use DateTimeImmutable;
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
        $this->otherKey = self::activeKey($this->other, Keys::pair()->kid);
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
        $acmeKey = self::activeKey($this->acme, Keys::pair()->kid);
        $this->repository->save($acmeKey);

        // When / Then
        static::assertSame($acmeKey, $this->repository->find($this->acme, Keys::pair()->kid));
        static::assertSame($this->otherKey, $this->repository->find($this->other, Keys::pair()->kid));
    }

    #[Test]
    public function anActiveKeyIsFoundActiveAndPublished(): void
    {
        // Given
        $acmeKey = self::activeKey($this->acme, Keys::pair()->kid);
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
        $key = self::activeKey($this->acme, Keys::pair()->kid);
        $key->startRetiring(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
        $this->repository->save($key);

        // When / Then
        static::assertNull($this->repository->findActive($this->acme, SignatureAlgorithm::RS256));
        static::assertSame([$key], $this->repository->findPublished($this->acme));
    }

    #[Test]
    public function aStagedKeyIsPublishedButNotActive(): void
    {
        // Given
        $key = new SigningKey(Keys::pair()->kid, $this->acme, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now());
        $this->repository->save($key);

        // When / Then
        static::assertNull($this->repository->findActive($this->acme, SignatureAlgorithm::RS256));
        static::assertSame([$key], $this->repository->findPublished($this->acme));
    }

    #[Test]
    public function aRetiredKeyIsFoundButNotPublished(): void
    {
        // Given
        $key = self::activeKey($this->acme, Keys::pair()->kid);
        $key->startRetiring(Fixtures::now(), Fixtures::now());
        $key->retire(Fixtures::now());
        $this->repository->save($key);

        // When / Then
        static::assertSame($key, $this->repository->find($this->acme, Keys::pair()->kid));
        static::assertSame([], $this->repository->findPublished($this->acme));
    }

    /**
     * SigningKeyRepositoryInterface::findPublished(): in creation order, whatever the order of the writes.
     */
    #[Test]
    public function thePublishedKeysComeInCreationOrder(): void
    {
        // Given
        $newest = self::activeKey($this->acme, Keys::pair()->kid, Fixtures::now());
        $oldest = new SigningKey(Keys::otherPair()->kid, $this->acme, SignatureAlgorithm::RS256, Keys::otherPair()->publicJwk, 'sealed', Fixtures::now()->modify('-1 day'));
        $this->repository->save($newest);
        $this->repository->save($oldest);

        // When / Then
        static::assertSame([$oldest, $newest], $this->repository->findPublished($this->acme));
    }

    private static function activeKey(Tenant $tenant, string $kid, ?DateTimeImmutable $createdAt = null): SigningKey
    {
        $key = new SigningKey($kid, $tenant, SignatureAlgorithm::RS256, [
            'kid' => $kid,
        ] + Keys::pair()->publicJwk, 'sealed', $createdAt ?? Fixtures::now());
        $key->activate($createdAt ?? Fixtures::now());

        return $key;
    }
}
