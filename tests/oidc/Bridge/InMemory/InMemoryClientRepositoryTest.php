<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\InMemory;

use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class InMemoryClientRepositoryTest extends TestCase
{
    private Tenant $tenant;

    private Client $client;

    private InMemoryClientRepository $repository;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->repository = new InMemoryClientRepository();
        $this->client = Clients::public($this->tenant);
        $this->repository->save($this->client);
        $this->repository->save(Clients::public(Fixtures::tenant('other', 'https://id.other.example'), 'elsewhere'));
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
        yield 'a client of another tenant' => [
            static fn (self $test): Tenant => $test->tenant,
            'elsewhere',
        ];
        yield 'the client from another tenant' => [
            static fn (self $test): Tenant => Fixtures::tenant('other', 'https://id.other.example'),
            'spa',
        ];
        yield 'an unknown id' => [
            static fn (self $test): Tenant => $test->tenant,
            'nobody',
        ];
    }

    #[Test]
    public function theTenantIssuesTheFormatAClientOfItsIsRegisteredFor(): void
    {
        // When / Then
        static::assertTrue($this->repository->issuesAccessTokensIn($this->tenant, AccessTokenFormat::Jwt));
    }

    #[Test]
    public function theTenantDoesNotIssueAFormatNoneOfItsClientsIsRegisteredFor(): void
    {
        // When / Then
        static::assertFalse($this->repository->issuesAccessTokensIn($this->tenant, AccessTokenFormat::Opaque));
    }

    /**
     * RFC 9126 §5: a tenant requires a pushed request when every client registered there does.
     */
    #[Test]
    public function theTenantRequiresAPushedRequestWhenEveryClientOfItsDoes(): void
    {
        // Given
        $repository = new InMemoryClientRepository();
        $repository->save(Clients::pushingOnly($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET)));

        // When / Then
        static::assertTrue($repository->requiresPushedAuthorizationRequests($this->tenant));
    }

    /**
     * One client that may still start an ordinary request is what makes the answer false, the
     * requirement being carried by the clients and by nothing global.
     */
    #[Test]
    public function oneClientThatDoesNotRequireItMakesTheTenantRequireNothing(): void
    {
        // Given
        $this->repository->save(Clients::pushingOnly($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET)));

        // When / Then
        static::assertFalse($this->repository->requiresPushedAuthorizationRequests($this->tenant));
    }

    /**
     * A tenant no client is registered for requires nothing of anybody.
     */
    #[Test]
    public function aTenantWithoutClientsRequiresNothing(): void
    {
        // When / Then
        static::assertFalse(new InMemoryClientRepository()->requiresPushedAuthorizationRequests($this->tenant));
    }

    #[Test]
    public function theClientsOfAnotherTenantDoNotCount(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->repository->save(Clients::confidential($other, new FakePasswordHasher()->hash(Clients::SECRET), clientId: 'api', accessTokenFormat: AccessTokenFormat::Opaque));

        // When / Then
        static::assertFalse($this->repository->issuesAccessTokensIn($this->tenant, AccessTokenFormat::Opaque));
    }

    /**
     * OIDC Registration §2: "none" is announced when a client of the tenant registered it, and by one
     * client, not by all of them, since one is enough to send an unsigned object.
     */
    #[Test]
    public function theTenantReadsUnsignedRequestObjectsWhenOneOfItsClientsRegisteredThem(): void
    {
        // Given
        $this->repository->save(Clients::sendingRequestObjects($this->tenant, new UnsignedRequestObjects()));

        // When / Then
        static::assertTrue($this->repository->acceptsUnsignedRequestObjects($this->tenant));
    }

    #[Test]
    public function aTenantWhoseClientsAllSignTheirRequestObjectsReadsNoUnsignedOne(): void
    {
        // Given
        $this->repository->save(Clients::sendingRequestObjects($this->tenant));

        // When / Then
        static::assertFalse($this->repository->acceptsUnsignedRequestObjects($this->tenant));
    }

    #[Test]
    public function theUnsignedRequestObjectsOfAnotherTenantDoNotCount(): void
    {
        // Given
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $this->repository->save(Clients::sendingRequestObjects($other, new UnsignedRequestObjects()));

        // When / Then
        static::assertFalse($this->repository->acceptsUnsignedRequestObjects($this->tenant));
    }
}
