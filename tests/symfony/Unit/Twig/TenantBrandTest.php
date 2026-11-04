<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Twig;

use App\Http\TenantPresentation;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\LogoUri;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Tenant\TenantLook;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\Uid\Uuid;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;
use Twig\TwigFunction;

/**
 * Architecture §5.2
 */
final class TenantBrandTest extends TestCase
{
    #[Test]
    public function theLogoOfTheTenantStandsUnderItsName(): void
    {
        // Given
        $brand = self::brand(new TenantLook(new LogoUri('https://acme.example/logo.svg')));

        // When / Then
        static::assertSame(['https://acme.example/logo.svg'], $brand->filter('header[data-tenant="brand"] img[data-tenant="logo"]')->extract(['src']));
    }

    #[Test]
    public function theNameOfTheTenantStandsInForTheImage(): void
    {
        // Given
        $brand = self::brand(new TenantLook(new LogoUri('https://acme.example/logo.svg')));

        // When / Then
        static::assertSame(['Acme'], $brand->filter('img[data-tenant="logo"]')->extract(['alt']));
    }

    /**
     * Referrer Policy §8.3
     */
    #[Test]
    public function theLogoIsLoadedWithoutTellingItsHostWhereTheReaderWas(): void
    {
        // Given
        $brand = self::brand(new TenantLook(new LogoUri('https://acme.example/logo.svg')));

        // When / Then
        static::assertSame(['no-referrer'], $brand->filter('img[data-tenant="logo"]')->extract(['referrerpolicy']));
    }

    #[Test]
    public function aTenantThatDeclaredNoLogoShowsNothing(): void
    {
        // Given
        $brand = self::brand(TenantLook::none());

        // When / Then
        static::assertCount(0, $brand->filter('header[data-tenant="brand"]'));
    }

    #[Test]
    public function aTenantThatDeclaredColoursAloneShowsNothing(): void
    {
        // Given
        $brand = self::brand(new TenantLook(primaryColor: '#1b4b8f', primaryContentColor: '#ffffff'));

        // When / Then
        static::assertCount(0, $brand->filter('header[data-tenant="brand"]'));
    }

    #[Test]
    public function aPageWithNoTenantToNameShowsNothing(): void
    {
        // Given
        $brand = self::render(null);

        // When / Then
        static::assertCount(0, $brand->filter('header[data-tenant="brand"]'));
    }

    private static function brand(TenantLook $look): Crawler
    {
        return self::render(TenantPresentation::of(
            new Tenant(Uuid::v7(), 'acme', new Issuer('https://id.acme.example'), 'Acme', Fixtures::now(), look: $look),
        ));
    }

    private static function render(?TenantPresentation $presentation): Crawler
    {
        $loader = new FilesystemLoader();
        $loader->addPath(__DIR__ . '/../../../../apps/op/templates/beffroi', 'Beffroi');
        $twig = new Environment($loader);
        $twig->addFunction(new TwigFunction('beffroi_tenant', static fn (): ?TenantPresentation => $presentation));

        return new Crawler($twig->render('@Beffroi/_brand.html.twig'));
    }
}
