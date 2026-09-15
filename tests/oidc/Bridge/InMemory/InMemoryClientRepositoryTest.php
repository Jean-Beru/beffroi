<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\InMemory;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class InMemoryClientRepositoryTest extends TestCase
{
    #[Test]
    public function itFindsAClientByIdInItsTenantOnly(): void
    {
        $tenant = Fixtures::tenant();
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $repository = new InMemoryClientRepository();
        $client = Clients::public($tenant);
        $repository->save($client);
        $repository->save(Clients::public($other, 'elsewhere'));

        static::assertSame($client, $repository->findByClientId($tenant, 'spa'));
        static::assertNull($repository->findByClientId($tenant, 'elsewhere'));
        static::assertNull($repository->findByClientId($other, 'spa'));
        static::assertNull($repository->findByClientId($tenant, 'nobody'));
    }
}
