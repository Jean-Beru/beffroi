<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Tenant;

use Heidi\Bundle\Tenant\TenantFactory;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class TenantFactoryTest extends TestCase
{
    /**
     * Architecture §5.1: the tenant is the configuration; RFC 9562 §5.5 gives it a stable identifier from
     * its slug, the same in every process.
     */
    #[Test]
    public function theTenantIsBuiltFromTheConfiguration(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test/idp', 'main', 'Main tenant', new MockClock(Fixtures::now()));

        // When
        $tenant = $factory->create();

        // Then
        static::assertSame('https://op.test/idp', (string) $tenant->issuer);
        static::assertSame('main', $tenant->slug);
        static::assertSame('Main tenant', $tenant->name);
        static::assertEquals(Fixtures::now(), $tenant->createdAt);
    }

    /**
     * RFC 9562 §5.5: the identifier comes from the slug, the same in every process.
     */
    #[Test]
    public function theIdentifierIsStableAcrossProcessesAndIssuers(): void
    {
        // Given
        $clock = new MockClock(Fixtures::now());

        // When
        $tenant = new TenantFactory('https://op.test/idp', 'main', 'Main tenant', $clock)->create();
        $again = new TenantFactory('https://other.test', 'main', null, $clock)->create();

        // Then
        static::assertTrue($tenant->id->equals(TenantFactory::identifier('main')));
        static::assertTrue($tenant->equals($again));
        static::assertFalse($tenant->id->equals(TenantFactory::identifier('other')));
    }

    #[Test]
    public function theNameDefaultsToTheHostOfTheIssuer(): void
    {
        // Given
        $factory = new TenantFactory('https://other.test', 'main', null, new MockClock());

        // When
        $tenant = $factory->create();

        // Then
        static::assertSame('other.test', $tenant->name);
    }

    #[Test]
    public function anIssuerTheCoreRefusesIsRefused(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test/', 'main', null, new MockClock());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $factory->create();
    }

    #[Test]
    public function aSlugTheCoreRefusesIsRefused(): void
    {
        // Given
        $factory = new TenantFactory('https://op.test', 'Not A Slug', null, new MockClock());

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $factory->create();
    }
}
