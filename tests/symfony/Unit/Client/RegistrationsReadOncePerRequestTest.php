<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Client;

use App\Client\RegistrationsReadOncePerRequest;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Port\ClientSourceInterface;
use Beffroi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3
 */
final class RegistrationsReadOncePerRequestTest extends TestCase
{
    #[Test]
    public function theRegistrationsOfATenantAreReadOnceInARequest(): void
    {
        // Given
        $store = self::store();
        $registrations = new RegistrationsReadOncePerRequest($store);
        $tenant = Fixtures::tenant();
        $registrations->registrationsIn($tenant);

        // When
        $read = $registrations->registrationsIn($tenant);

        // Then
        static::assertCount(1, $read);
        static::assertSame(1, $store->reads);
    }

    #[Test]
    public function theRegistrationsAreReadAgainOnceTheKernelResetsThem(): void
    {
        // Given
        $store = self::store();
        $registrations = new RegistrationsReadOncePerRequest($store);
        $tenant = Fixtures::tenant();
        $registrations->registrationsIn($tenant);
        $registrations->reset();

        // When
        $registrations->registrationsIn($tenant);

        // Then
        static::assertSame(2, $store->reads);
    }

    #[Test]
    public function eachTenantHasItsRegistrationsRead(): void
    {
        // Given
        $store = self::store();
        $registrations = new RegistrationsReadOncePerRequest($store);
        $registrations->registrationsIn(Fixtures::tenant('acme'));

        // When
        $registrations->registrationsIn(Fixtures::tenant('globex', 'https://id.globex.example'));

        // Then
        static::assertSame(2, $store->reads);
    }

    /**
     * @return ClientSourceInterface&object{reads: int}
     */
    private static function store(): ClientSourceInterface
    {
        return new class implements ClientSourceInterface {
            public int $reads = 0;

            public function findByClientId(Tenant $tenant, string $clientId): ?Client
            {
                return null;
            }

            public function registrationsIn(Tenant $tenant): iterable
            {
                ++$this->reads;
                yield Clients::public($tenant)->registration;
            }
        };
    }
}
