<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\RegisteredClients;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedProtectedResources;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Resource\ResourceIndicator;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9728 §4 "protected_resources": which resources a client of this tenant may name in a "resource"
 * parameter (RFC 8707 §2). What is announced is what the clients registered, read from them.
 */
final class AnnouncedProtectedResourcesTest extends TestCase
{
    #[Test]
    public function itAnnouncesTheResourcesTheClientsOfTheTenantRegistered(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        // a client of another tenant first, whose resources are no business of this one
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $clients->save(Clients::public($other, resources: [new ResourceIndicator('https://files.example.com/')]));
        $clients->save(Clients::public($tenant, resources: Clients::resources()));
        $announced = new AnnouncedProtectedResources(new RegisteredClients([$clients]));

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $members['protected_resources']);
    }

    /**
     * A resource two clients registered is one resource of the tenant.
     */
    #[Test]
    public function itAnnouncesAResourceTwoClientsRegisteredOnce(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, resources: Clients::resources()));
        $clients->save(Clients::public($tenant, 'other-spa', Clients::resources()));
        $announced = new AnnouncedProtectedResources(new RegisteredClients([$clients]));

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $members['protected_resources']);
    }

    /**
     * A member a client would read as "no resource is acceptable here" is not written at all.
     */
    #[Test]
    public function itAnnouncesNothingWhenNoClientRegisteredAResource(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant));
        $announced = new AnnouncedProtectedResources(new RegisteredClients([$clients]));

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame([], $members);
    }

    /**
     * The resources of one tenant are no business of another.
     */
    #[Test]
    public function itAnnouncesNothingOfAnotherTenant(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, resources: Clients::resources()));
        $announced = new AnnouncedProtectedResources(new RegisteredClients([$clients]));

        // When
        $members = $announced->metadata(Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        static::assertSame([], $members);
    }
}
