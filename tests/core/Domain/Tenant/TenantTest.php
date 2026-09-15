<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Tenant;

use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class TenantTest extends TestCase
{
    #[Test]
    #[DataProvider('provideInvalidSlugs')]
    public function itRejectsASlugThatCouldNotBeAPathSegmentOrAHostLabel(string $slug): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Tenant(Uuid::v7(), $slug, new Issuer('https://id.example'), 'Acme', Fixtures::now());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidSlugs(): iterable
    {
        yield 'empty' => [''];
        yield 'uppercase' => ['Acme'];
        yield 'leading hyphen' => ['-acme'];
        yield 'trailing hyphen' => ['acme-'];
        yield 'space' => ['ac me'];
        yield 'too long' => [str_repeat('a', 64)];
    }

    #[Test]
    public function itCanBeRenamedButNotToNothing(): void
    {
        $tenant = Fixtures::tenant();
        $tenant->rename('Acme Corporation');
        static::assertSame('Acme Corporation', $tenant->name);

        $this->expectException(InvalidArgumentException::class);
        $tenant->rename('');
    }

    #[Test]
    public function itCannotBeCreatedWithoutAName(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Tenant(Uuid::v7(), 'acme', new Issuer('https://id.example'), '', Fixtures::now());
    }

    #[Test]
    public function twoTenantsAreEqualByIdentifierOnly(): void
    {
        $id = Uuid::v7();
        $a = new Tenant($id, 'acme', new Issuer('https://a.example'), 'A', Fixtures::now());
        $b = new Tenant($id, 'other', new Issuer('https://b.example'), 'B', Fixtures::now());

        static::assertTrue($a->equals($b));
        static::assertFalse($a->equals(Fixtures::tenant()));
    }
}
