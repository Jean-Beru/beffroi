<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Client;

use function array_map;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\ClientInventory;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Client\InventoriedClient;
use Beffroi\Oidc\Port\ClientInventoryInterface;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0009: every client of a tenant, whatever holds it, each saying where it came from. What is
 * listed is what is wired, so a source added to a deployment is in the list by being wired.
 */
final class ClientInventoryTest extends TestCase
{
    #[Test]
    public function itListsWhatEverySourceHolds(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $inventory = new ClientInventory([
            self::sourceOf($tenant, 'declared'),
            self::sourceOf($tenant, 'registered'),
        ]);

        // When
        $clients = [...$inventory->inventoryIn($tenant)];

        // Then
        static::assertSame(
            ['declared', 'registered'],
            array_map(static fn (InventoriedClient $client): string => $client->clientId, $clients),
        );
    }

    /**
     * A source wired later brings nothing with it: what the list holds is what the sources hold, and
     * nothing here counts how many there are.
     */
    #[Test]
    public function aDeploymentThatWiresOneSourceListsThatOne(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $inventory = new ClientInventory([self::sourceOf($tenant, 'declared')]);

        // When
        $clients = [...$inventory->inventoryIn($tenant)];

        // Then
        static::assertCount(1, $clients);
    }

    #[Test]
    public function aTenantWithNoClientIsListedAsHavingNone(): void
    {
        // Given
        $inventory = new ClientInventory([self::sourceOf(Fixtures::tenant(), 'declared')]);

        // When
        $clients = [...$inventory->inventoryIn(Fixtures::tenant('other', 'https://id.other.example'))];

        // Then
        static::assertSame([], $clients);
    }

    /**
     * The client a request would be served from is the one the first source that holds the identifier
     * answers, so that is the one shown.
     */
    #[Test]
    public function itFindsTheClientTheFirstSourceThatHoldsItHolds(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $inventory = new ClientInventory([
            self::sourceOf($tenant, 'shared'),
            self::sourceOf($tenant, 'shared'),
        ]);

        // When
        $client = $inventory->find($tenant, 'shared');

        // Then
        static::assertSame('shared', $client?->clientId);
    }

    #[Test]
    public function anIdentifierNoSourceHoldsNamesNoClient(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $inventory = new ClientInventory([self::sourceOf($tenant, 'declared')]);

        // When
        $client = $inventory->find($tenant, 'a-client-nobody-declared');

        // Then
        static::assertNull($client);
    }

    private static function sourceOf(Tenant $tenant, string $clientId): ClientInventoryInterface
    {
        $source = new InMemoryClientRepository();
        $source->save(Clients::public($tenant, $clientId));

        return $source;
    }
}
