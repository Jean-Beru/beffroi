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
    public function theTenantIsBuiltFromTheConfigurationWithAStableIdentifier(): void
    {
        $clock = new MockClock(Fixtures::now());

        $tenant = new TenantFactory('https://op.test/idp', 'main', 'Main tenant', $clock)
            ->create();
        $again = new TenantFactory('https://other.test', 'main', null, $clock)
            ->create();

        static::assertSame('https://op.test/idp', (string) $tenant->issuer);
        static::assertSame('main', $tenant->slug);
        static::assertSame('Main tenant', $tenant->name);
        static::assertEquals(Fixtures::now(), $tenant->createdAt);
        static::assertTrue($tenant->id->equals(TenantFactory::identifier('main')));
        static::assertTrue($tenant->equals($again));
        static::assertFalse($tenant->id->equals(TenantFactory::identifier('other')));
        static::assertSame('other.test', $again->name);
    }

    #[Test]
    public function anIssuerTheCoreRefusesIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new TenantFactory('https://op.test/', 'main', null, new MockClock())
            ->create();
    }

    #[Test]
    public function aSlugTheCoreRefusesIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new TenantFactory('https://op.test', 'Not A Slug', null, new MockClock())
            ->create();
    }
}
