<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Tenant;

use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Tenant\TenantContact;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\Uid\Uuid;

final class TenantTest extends TestCase
{
    #[Test]
    #[DataProvider('provideInvalidSlugs')]
    public function itRejectsASlugThatCouldNotBeAPathSegmentOrAHostLabel(string $slug): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
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
        yield 'a line feed behind a slug that would pass' => ["acme\n"];
    }

    #[Test]
    public function aTenantDeclaresNoLookUntilItAdoptsOne(): void
    {
        // When / Then
        static::assertFalse(Fixtures::tenant()->look->isDeclared());
    }

    #[Test]
    public function itAdoptsTheLookOfItsPages(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $look = new TenantLook(new LogoUri('https://acme.example/logo.svg'), '#1b4b8f', '#ffffff');

        // When
        $tenant->adoptLook($look);

        // Then
        static::assertTrue($tenant->look->equals($look));
    }

    #[Test]
    public function aTenantGivesNoContactUntilItAdoptsOne(): void
    {
        // When / Then
        static::assertNull(Fixtures::tenant()->contact);
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function itAdoptsTheContactItGivesItsPeople(): void
    {
        // Given
        $tenant = Fixtures::tenant();

        // When
        $tenant->adoptContact(new TenantContact('security@acme.example'));

        // Then
        static::assertSame('security@acme.example', $tenant->contact?->value);
    }

    #[Test]
    public function itTakesItsContactBack(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $tenant->adoptContact(new TenantContact('security@acme.example'));

        // When
        $tenant->adoptContact(null);

        // Then
        static::assertNull($tenant->contact);
    }

    #[Test]
    public function itCanBeRenamed(): void
    {
        // Given
        $tenant = Fixtures::tenant();

        // When
        $tenant->rename('Acme Corporation');

        // Then
        static::assertSame('Acme Corporation', $tenant->name);
    }

    #[Test]
    public function itCannotBeRenamedToNothing(): void
    {
        // Given
        $tenant = Fixtures::tenant();

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        $tenant->rename('');
    }

    #[Test]
    public function itCannotBeCreatedWithoutAName(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new Tenant(Uuid::v7(), 'acme', new Issuer('https://id.example'), '', Fixtures::now());
    }

    #[Test]
    public function twoTenantsWithTheSameIdentifierAreEqualWhateverTheRest(): void
    {
        // Given
        $id = Uuid::v7();
        $a = new Tenant($id, 'acme', new Issuer('https://a.example'), 'A', Fixtures::now());
        $b = new Tenant($id, 'other', new Issuer('https://b.example'), 'B', Fixtures::now());

        // When / Then
        static::assertTrue($a->equals($b));
    }

    #[Test]
    public function twoTenantsWithDifferentIdentifiersAreNotEqual(): void
    {
        // Given
        $tenant = new Tenant(Uuid::v7(), 'acme', new Issuer('https://a.example'), 'A', Fixtures::now());

        // When / Then
        static::assertFalse($tenant->equals(Fixtures::tenant()));
    }
}
