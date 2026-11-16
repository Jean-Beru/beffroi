<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedProtectedResources;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationAdministrationResource;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9728 §4, RFC 8707 §2
 */
final class AnnouncedProtectedResourcesTest extends TestCase
{
    #[Test]
    public function itAnnouncesTheResourcesTheClientsOfTheTenantRegistered(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $other = Fixtures::tenant('other', 'https://id.other.example');
        $clients->save(Clients::public($other, resources: [new ResourceIndicator('https://files.example.com/')]));
        $clients->save(Clients::public($tenant, resources: Clients::resources()));
        $announced = new AnnouncedProtectedResources(new RegisteredClients([$clients]), new ConfigurationAdministrationResource('none'));

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $members['protected_resources']);
    }

    /**
     * Decision 0038
     */
    #[Test]
    public function itNeverAnnouncesTheAdministrationApi(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, resources: [new ResourceIndicator(Clients::CALENDAR), new ResourceIndicator('https://admin.acme.example/')]));
        $announced = new AnnouncedProtectedResources(
            new RegisteredClients([$clients]),
            new ConfigurationAdministrationResource($tenant->slug, 'https://admin.acme.example/'),
        );

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame([Clients::CALENDAR], $members['protected_resources']);
    }

    #[Test]
    public function itAnnouncesAResourceTwoClientsRegisteredOnce(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, resources: Clients::resources()));
        $clients->save(Clients::public($tenant, 'other-spa', Clients::resources()));
        $announced = new AnnouncedProtectedResources(new RegisteredClients([$clients]), new ConfigurationAdministrationResource('none'));

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $members['protected_resources']);
    }

    #[Test]
    public function itAnnouncesNothingWhenNoClientRegisteredAResource(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant));
        $announced = new AnnouncedProtectedResources(new RegisteredClients([$clients]), new ConfigurationAdministrationResource('none'));

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame([], $members);
    }

    #[Test]
    public function itAnnouncesNothingOfAnotherTenant(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, resources: Clients::resources()));
        $announced = new AnnouncedProtectedResources(new RegisteredClients([$clients]), new ConfigurationAdministrationResource('none'));

        // When
        $members = $announced->metadata(Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        static::assertSame([], $members);
    }
}
