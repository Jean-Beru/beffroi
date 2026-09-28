<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Client;

use function array_map;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\RegisteredClients;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Shapes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §4.1, issue #334: the clients of a tenant come from every source the wiring holds, and
 * what a question about the set of them means is answered here. A deployment declares some of its clients
 * and registers others; nothing that asks about them learns there are two places.
 */
final class RegisteredClientsTest extends TestCase
{
    private Tenant $tenant;

    private InMemoryClientRepository $declared;

    private InMemoryClientRepository $registered;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->declared = new InMemoryClientRepository();
        $this->registered = new InMemoryClientRepository();
    }

    #[Test]
    public function aClientOfAnySourceIsResolvedByItsIdentifier(): void
    {
        // Given
        $this->registered->save(Clients::public($this->tenant, 'registered-spa'));
        $clients = $this->clients();

        // When
        $client = $clients->findByClientId($this->tenant, 'registered-spa');

        // Then
        static::assertSame('registered-spa', $client?->registration->clientId);
    }

    #[Test]
    public function anIdentifierNoSourceHoldsIsResolvedByNobody(): void
    {
        // Given
        $this->declared->save(Clients::public($this->tenant));
        $clients = $this->clients();

        // When / Then
        static::assertNull($clients->findByClientId($this->tenant, 'nobody'));
    }

    /**
     * A client belongs to the tenant it was registered under, whichever source holds it.
     */
    #[Test]
    public function aClientOfAnotherTenantIsResolvedByNobody(): void
    {
        // Given
        $this->registered->save(Clients::public($this->tenant, 'registered-spa'));
        $clients = $this->clients();

        // When / Then
        static::assertNull($clients->findByClientId(Fixtures::tenant('other', 'https://id.other.example'), 'registered-spa'));
    }

    /**
     * RFC 8707 §2, RFC 9728 §4: the resources of a tenant are what its clients registered, whichever
     * source holds them, each named once.
     */
    #[Test]
    public function theResourcesOfATenantAreThoseOfEverySource(): void
    {
        // Given
        $this->declared->save(Clients::public($this->tenant, resources: [new ResourceIndicator(Clients::CALENDAR)]));
        $this->registered->save(Clients::public($this->tenant, 'registered-spa', [
            new ResourceIndicator(Clients::CALENDAR),
            new ResourceIndicator(Clients::CONTACTS),
        ]));
        $clients = $this->clients();

        // When
        $resources = $clients->resourcesRegisteredIn($this->tenant);

        // Then
        static::assertSame(
            [Clients::CALENDAR, Clients::CONTACTS],
            array_map(static fn (ResourceIndicator $resource): string => $resource->value, $resources),
        );
    }

    /**
     * OIDC Discovery §3, issue #278: the scopes of a tenant are what its clients registered, whichever
     * source holds them, each named once.
     */
    #[Test]
    public function theScopesOfATenantAreThoseOfEverySource(): void
    {
        // Given
        $this->declared->save(Clients::public($this->tenant, allowedScopes: new Scopes([Scope::openid(), new Scope('billing.read')])));
        $this->registered->save(Clients::public($this->tenant, 'registered-spa', allowedScopes: new Scopes([Scope::openid(), new Scope('billing.write')])));
        $clients = $this->clients();

        // When
        $scopes = $clients->scopesRegisteredIn($this->tenant);

        // Then
        static::assertSame(
            ['openid', 'billing.read', 'billing.write'],
            array_map(static fn (Scope $scope): string => $scope->value, $scopes),
        );
    }

    /**
     * Architecture §4.6: a shape one client of the tenant registered is a shape the provider writes for
     * it, whichever source that client came from.
     */
    #[Test]
    public function aShapeOneSourceRegisteredIsIssuedByTheTenant(): void
    {
        // Given
        $this->declared->save(Clients::public($this->tenant));
        $this->registered->save(Clients::confidential(
            $this->tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            clientId: 'registered-api',
            accessTokenShape: Shapes::opaque(),
        ));
        $clients = $this->clients();

        // When / Then
        static::assertTrue($clients->issuesAccessTokensIn($this->tenant, Shapes::opaque()));
    }

    #[Test]
    public function aShapeNoSourceRegisteredIsIssuedByNobody(): void
    {
        // Given
        $this->declared->save(Clients::public($this->tenant));
        $clients = $this->clients();

        // When / Then
        static::assertFalse($clients->issuesAccessTokensIn($this->tenant, Shapes::opaque()));
    }

    /**
     * RFC 9126 §5: the document says a request must be pushed when every client of the tenant says so,
     * which now means every client of every source.
     */
    #[Test]
    public function theTenantRequiresAPushedRequestWhenEveryClientOfEverySourceDoes(): void
    {
        // Given
        $hash = new FakePasswordHasher()->hash(Clients::SECRET);
        $this->declared->save(Clients::pushingOnly($this->tenant, $hash));
        $this->registered->save(Clients::pushingOnly($this->tenant, $hash, 'registered-fapi'));
        $clients = $this->clients();

        // When / Then
        static::assertTrue($clients->requiresPushedAuthorizationRequests($this->tenant));
    }

    /**
     * One client that may still start an ordinary request is enough, and a source that holds none says
     * nothing of the others: a source with no client of the tenant answers about no client, not "no".
     */
    #[Test]
    public function oneClientOfOneSourceThatStartsAnOrdinaryRequestIsEnough(): void
    {
        // Given
        $this->declared->save(Clients::pushingOnly($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET)));
        $this->registered->save(Clients::public($this->tenant, 'registered-spa'));
        $clients = $this->clients();

        // When / Then
        static::assertFalse($clients->requiresPushedAuthorizationRequests($this->tenant));
    }

    /**
     * A source that holds no client of the tenant takes nothing away from what the others require.
     */
    #[Test]
    public function aSourceWithNoClientOfTheTenantRequiresNothingOfIt(): void
    {
        // Given
        $this->declared->save(Clients::pushingOnly($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET)));
        $clients = $this->clients();

        // When / Then
        static::assertTrue($clients->requiresPushedAuthorizationRequests($this->tenant));
    }

    /**
     * RFC 9126 §5: a tenant no source holds a client of requires nothing of anybody.
     */
    #[Test]
    public function aTenantWithNoClientAtAllRequiresNothingOfAnybody(): void
    {
        // Given
        $clients = $this->clients();

        // When / Then
        static::assertFalse($clients->requiresPushedAuthorizationRequests($this->tenant));
    }

    /**
     * OIDC Registration §2, decision 0012: the document announces "none" when a client of the tenant
     * registered it, whichever source holds that client.
     */
    #[Test]
    public function anUnsignedRequestObjectOfOneSourceIsAnnouncedByTheTenant(): void
    {
        // Given
        $this->declared->save(Clients::public($this->tenant));
        $this->registered->save(Clients::sendingRequestObjects($this->tenant, new UnsignedRequestObjects(), clientId: 'registered-jar'));
        $clients = $this->clients();

        // When / Then
        static::assertTrue($clients->acceptsUnsignedRequestObjects($this->tenant));
    }

    #[Test]
    public function aTenantWhoseClientsAllSignTheirRequestObjectsReadsNoUnsignedOne(): void
    {
        // Given
        $this->declared->save(Clients::public($this->tenant));
        $this->registered->save(Clients::sendingRequestObjects($this->tenant, clientId: 'registered-jar'));
        $clients = $this->clients();

        // When / Then
        static::assertFalse($clients->acceptsUnsignedRequestObjects($this->tenant));
    }

    /**
     * The clients of one tenant are no business of another, whichever source holds them.
     */
    #[Test]
    public function anotherTenantIsAnsweredAboutItsOwnClientsAlone(): void
    {
        // Given
        $this->declared->save(Clients::public($this->tenant, resources: Clients::resources()));
        $this->registered->save(Clients::public($this->tenant, 'registered-spa', allowedScopes: new Scopes([new Scope('billing.read')])));
        $clients = $this->clients();
        $other = Fixtures::tenant('other', 'https://id.other.example');

        // When / Then
        static::assertSame([], $clients->resourcesRegisteredIn($other));
        static::assertSame([], $clients->scopesRegisteredIn($other));
        static::assertFalse($clients->issuesAccessTokensIn($other, Shapes::jwt()));
        static::assertFalse($clients->requiresPushedAuthorizationRequests($other));
        static::assertFalse($clients->acceptsUnsignedRequestObjects($other));
    }

    private function clients(): RegisteredClients
    {
        return new RegisteredClients([$this->declared, $this->registered]);
    }
}
