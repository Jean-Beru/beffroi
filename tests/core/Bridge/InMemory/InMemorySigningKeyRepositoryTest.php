<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Bridge\InMemory;

use Heidi\Core\Bridge\InMemory\InMemorySigningKeyRepository;
use Heidi\Core\Domain\Key\SignatureAlgorithm;
use Heidi\Core\Domain\Key\SigningKey;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class InMemorySigningKeyRepositoryTest extends TestCase
{
    #[Test]
    public function keysAreScopedByTenantEvenWithTheSameKid(): void
    {
        $acme = Fixtures::tenant();
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $repository = new InMemorySigningKeyRepository();
        $acmeKey = new SigningKey(Keys::pair()->kid, $acme, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now());
        $otherKey = new SigningKey(Keys::pair()->kid, $other, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now());
        $repository->save($otherKey);

        static::assertNull($repository->findActive($acme, SignatureAlgorithm::RS256));
        static::assertSame([], $repository->findPublished($acme));

        $repository->save($acmeKey);

        static::assertSame($acmeKey, $repository->find($acme, Keys::pair()->kid));
        static::assertSame($otherKey, $repository->find($other, Keys::pair()->kid));
        static::assertSame($acmeKey, $repository->findActive($acme, SignatureAlgorithm::RS256));
        static::assertSame([$acmeKey], $repository->findPublished($acme));
        static::assertNull($repository->find($acme, 'unknown'));
    }

    #[Test]
    public function aRetiringKeyIsPublishedButNotActive(): void
    {
        $tenant = Fixtures::tenant();
        $repository = new InMemorySigningKeyRepository();
        $key = new SigningKey(Keys::pair()->kid, $tenant, SignatureAlgorithm::RS256, Keys::pair()->publicJwk, 'sealed', Fixtures::now());
        $key->startRetiring(Fixtures::now());
        $repository->save($key);

        static::assertNull($repository->findActive($tenant, SignatureAlgorithm::RS256));
        static::assertSame([$key], $repository->findPublished($tenant));
    }
}
