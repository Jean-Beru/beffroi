<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\InMemory;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class InMemoryClientRepositoryTest extends TestCase
{
    private Tenant $tenant;

    private Tenant $other;

    private Client $client;

    private InMemoryClientRepository $repository;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->other = Fixtures::tenant('other', 'https://id.other.example');
        $this->repository = new InMemoryClientRepository();
        $this->client = Clients::public($this->tenant);
        $this->repository->save($this->client);
        $this->repository->save(Clients::public($this->other, 'elsewhere'));
    }

    #[Test]
    public function itFindsAClientByIdInItsTenant(): void
    {
        // When / Then
        static::assertSame($this->client, $this->repository->findByClientId($this->tenant, 'spa'));
    }

    /**
     * @param callable(self): Tenant $tenant
     */
    #[Test]
    #[DataProvider('provideLookupsThatFindNothing')]
    public function itFindsNothingOutsideTheTenantOrForAnUnknownId(callable $tenant, string $clientId): void
    {
        // When / Then
        static::assertNull($this->repository->findByClientId($tenant($this), $clientId));
    }

    /**
     * @return iterable<string, array{callable(self): Tenant, string}>
     */
    public static function provideLookupsThatFindNothing(): iterable
    {
        yield 'a client of another tenant' => [static fn (self $test): Tenant => $test->tenant, 'elsewhere'];
        yield 'the client from another tenant' => [static fn (self $test): Tenant => $test->other, 'spa'];
        yield 'an unknown id' => [static fn (self $test): Tenant => $test->tenant, 'nobody'];
    }
}
