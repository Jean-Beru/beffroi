<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use Heidi\Bundle\Doctrine\TenantNotSynchronizedException;
use Heidi\Bundle\Doctrine\TenantProvider;
use Heidi\Bundle\Doctrine\TenantSynchronizer;
use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Domain\Tenant\Tenant;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\MockClock;
use Symfony\Contracts\Service\ResetInterface;

/**
 * Architecture §5.3: the tenant the services receive is the row, checked against the configuration; the
 * synchroniser writes the row from the configuration, once, and refuses to move an issuer.
 */
final class TenantProviderTest extends DatabaseTestCase
{
    #[Test]
    public function theTenantIsTheRowOfTheConfiguration(): void
    {
        $tenant = self::tenant();

        static::assertTrue($tenant->id->equals(TenantFactory::identifier('default')));
        static::assertSame('https://op.test', (string) $tenant->issuer);
        static::assertSame('op.test', $tenant->name);
        static::assertTrue(self::entityManager()->contains($tenant));
        static::assertSame($tenant, self::entityManager()->find(Tenant::class, $tenant->id));
    }

    /**
     * An entity is not a service: the instance lives as long as the unit of work. Between two requests
     * or two messages the kernel resets its services, Doctrine's registry among them, and the next
     * request gets the tenant of its own unit of work; a cleared entity manager forgets it as well.
     */
    #[Test]
    public function theInstanceIsForgottenWithTheUnitOfWork(): void
    {
        $provider = self::service('test.heidi.tenant_provider', TenantProvider::class);
        $first = $provider->provide();
        static::assertSame($first, $provider->provide());

        self::entityManager()
            ->clear();
        $second = $provider->provide();
        static::assertNotSame($first, $second);
        static::assertFalse(self::entityManager()->contains($first));
        static::assertTrue(self::entityManager()->contains($second));

        self::service('services_resetter', ResetInterface::class)
            ->reset();
        $third = $provider->provide();
        static::assertNotSame($second, $third);
        static::assertTrue(self::entityManager()->contains($third));
        static::assertTrue($third->id->equals($first->id));
    }

    #[Test]
    public function synchronisingAgainWritesNothing(): void
    {
        $synchronizer = self::service('test.heidi.tenant_synchronizer', TenantSynchronizer::class);
        $first = $synchronizer->synchronize();
        $again = $synchronizer->synchronize();

        static::assertSame($first, $again);
        static::assertSame($first, self::tenant());
    }

    #[Test]
    public function aMissingRowRefusesToServe(): void
    {
        $factory = self::factory('https://op.test', 'default', null);
        $provider = new TenantProvider($factory, self::registry());
        self::entityManager()
            ->createQuery('DELETE FROM Heidi\Core\Domain\Tenant\Tenant t')
            ->execute();

        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageMatches('/has no row yet/');

        $provider->provide();
    }

    #[Test]
    public function aRowThatDisagreesWithTheConfigurationRefusesToServe(): void
    {
        $provider = new TenantProvider(self::factory('https://other.test', 'default', null), self::registry());

        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageMatches('/stored with the issuer "https:\/\/op.test" and configured with "https:\/\/other.test"/');

        $provider->provide();
    }

    #[Test]
    public function aRenamedTenantRefusesToServeUntilSynchronised(): void
    {
        $factory = self::factory('https://op.test', 'default', 'Renamed');
        $provider = new TenantProvider($factory, self::registry());
        try {
            $provider->provide();
            static::fail('The row still carries the old name.');
        } catch (TenantNotSynchronizedException $exception) {
            static::assertStringContainsString('stored with the name "op.test" and configured with "Renamed"', $exception->getMessage());
        }

        $synchronized = new TenantSynchronizer($factory, self::registry())
            ->synchronize();
        self::reload();

        static::assertSame('Renamed', $synchronized->name);
        static::assertSame('Renamed', $provider->provide()->name);
    }

    /**
     * The issuer of a tenant does not change: every token issued so far names it. Another issuer is
     * another tenant, under another slug.
     */
    #[Test]
    public function theSynchroniserRefusesToMoveTheIssuer(): void
    {
        $synchronizer = new TenantSynchronizer(self::factory('https://moved.test', 'default', null), self::registry());

        $this->expectException(TenantNotSynchronizedException::class);
        $this->expectExceptionMessageMatches('/the issuer of a tenant does not change/');

        $synchronizer->synchronize();
    }

    #[Test]
    public function anotherSlugIsAnotherTenant(): void
    {
        $other = new TenantSynchronizer(self::factory('https://other.test', 'other', null), self::registry())
            ->synchronize();
        self::reload();

        static::assertTrue($other->id->equals(TenantFactory::identifier('other')));
        $stored = self::entityManager()->find(Tenant::class, $other->id) ?? static::fail('The other tenant was not stored.');
        static::assertTrue(new Issuer('https://other.test')->equals($stored->issuer));
        static::assertSame('https://op.test', (string) self::tenant()->issuer);
    }

    private static function factory(string $issuer, string $slug, ?string $name): TenantFactory
    {
        return new TenantFactory($issuer, $slug, $name, new MockClock(self::now()));
    }
}
