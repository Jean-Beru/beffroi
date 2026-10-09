<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\InMemory;

use DateTimeImmutable;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class InMemoryTenantKeyRepositoryTest extends TestCase
{
    private Tenant $acme;

    private Tenant $other;

    private InMemoryTenantKeyRepository $repository;

    private TenantKey $otherKey;

    protected function setUp(): void
    {
        $this->acme = Fixtures::tenant();
        $this->other = Fixtures::tenant('other', 'https://id.other.example');
        $this->repository = new InMemoryTenantKeyRepository();
        $this->otherKey = self::activeKey($this->other, Keys::pair()->kid);
        $this->repository->save($this->otherKey);
    }

    #[Test]
    public function aTenantWithoutKeysHasNoActiveKey(): void
    {
        // When / Then
        static::assertNull($this->repository->findActive($this->acme, Algorithms::rs256()));
    }

    #[Test]
    public function aTenantWithoutKeysPublishesNothing(): void
    {
        // When / Then
        static::assertSame([], $this->repository->findInService($this->acme));
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
        static::assertSame($acmeKey, $this->repository->findActive($this->acme, Algorithms::rs256()));
        static::assertSame([$acmeKey], $this->repository->findInService($this->acme));
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
        static::assertNull($this->repository->findActive($this->acme, Algorithms::rs256()));
        static::assertSame([$key], $this->repository->findInService($this->acme));
    }

    #[Test]
    public function aStagedKeyIsPublishedButNotActive(): void
    {
        // Given
        $key = new TenantKey(Keys::pair()->kid, $this->acme, Algorithms::rs256(), Keys::pair()->publicJwk, 'sealed', Fixtures::now(), Fixtures::now());
        $this->repository->save($key);

        // When / Then
        static::assertNull($this->repository->findActive($this->acme, Algorithms::rs256()));
        static::assertSame([$key], $this->repository->findInService($this->acme));
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
        static::assertSame([], $this->repository->findInService($this->acme));
    }

    /**
     * TenantKeyRepositoryInterface::findInService(): in creation order, whatever the order of the writes.
     */
    #[Test]
    public function thePublishedKeysComeInCreationOrder(): void
    {
        // Given
        $newest = self::activeKey($this->acme, Keys::pair()->kid, Fixtures::now());
        $oldest = new TenantKey(
            Keys::otherPair()->kid,
            $this->acme,
            Algorithms::rs256(),
            Keys::otherPair()->publicJwk,
            'sealed',
            Fixtures::now()->modify('-1 day'),
            Fixtures::now()->modify('-1 day'),
        );
        $this->repository->save($newest);
        $this->repository->save($oldest);

        // When / Then
        static::assertSame([$oldest, $newest], $this->repository->findInService($this->acme));
    }

    private static function activeKey(Tenant $tenant, string $kid, ?DateTimeImmutable $createdAt = null): TenantKey
    {
        $key = new TenantKey(
            $kid,
            $tenant,
            Algorithms::rs256(),
            [
                'kid' => $kid,
            ] + Keys::pair()->publicJwk,
            'sealed',
            $createdAt ?? Fixtures::now(),
            $createdAt ?? Fixtures::now(),
        );
        $key->activate($createdAt ?? Fixtures::now());

        return $key;
    }
}
