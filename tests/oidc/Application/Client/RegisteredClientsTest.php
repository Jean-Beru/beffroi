<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use function array_map;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Client\RequestObject\UnsignedRequestObjects;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Shapes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §4.1
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
     * RFC 8707 §2, RFC 9728 §4
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
     * OIDC Discovery §3
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
     * Architecture §4.6
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
     * RFC 9126 §5
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
     * RFC 9126 §5
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
     * OIDC Registration §2, Decision 0012
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
