<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\TenantPresentation;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #449: the one object a page is given of its tenant, flat, so that a template reads it without
 * walking to where each value is kept.
 */
final class TenantPresentationTest extends TestCase
{
    #[Test]
    public function itCarriesTheNameOfTheTenantAndTheLookItDeclared(): void
    {
        // Given
        $tenant = self::tenant(new TenantLook(new LogoUri('https://acme.example/logo.svg'), '#1b4b8f', '#ffffff'));

        // When
        $presentation = TenantPresentation::of($tenant);

        // Then
        static::assertSame('Acme', $presentation->name);
        static::assertSame('https://acme.example/logo.svg', $presentation->logoUri);
        static::assertSame('#1b4b8f', $presentation->primaryColor);
        static::assertSame('#ffffff', $presentation->primaryContentColor);
    }

    #[Test]
    public function aTenantThatDeclaredNoLookIsItsNameAndNothingElse(): void
    {
        // Given
        $tenant = self::tenant(TenantLook::none());

        // When
        $presentation = TenantPresentation::of($tenant);

        // Then
        static::assertSame('Acme', $presentation->name);
        static::assertNull($presentation->logoUri);
        static::assertNull($presentation->primaryColor);
        static::assertNull($presentation->primaryContentColor);
    }

    private static function tenant(TenantLook $look): Tenant
    {
        return new Tenant(Uuid::v7(), 'acme', new Issuer('https://id.acme.example'), 'Acme', Fixtures::now(), look: $look);
    }
}
