<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Twig;

use Beffroi\Bundle\Http\TenantPresentation;
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
 * Issue #449, architecture §5.2: the logo of the organisation the visitor came for, which the bundle
 * ships as a header with the name of that organisation as the text that stands in for the image.
 *
 * The fragment is rendered on an environment of its own, because what it reads is a function
 * ("beffroi_tenant()", TenantExtension) and what a deployment declares is one look: giving it the look to
 * render is giving it that function. It needs nothing else of the bundle, neither a catalogue nor a
 * router, which is what makes that possible.
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
     * The browser of the reader loads the image from a host the tenant named, and tells it nothing of
     * where that reader was (Referrer Policy §8.3), as the logo of a client on the consent page does.
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

    /**
     * A colour is a look, and the look of these pages is the application's: the bundle hands the value to
     * the template and writes no style of its own.
     */
    #[Test]
    public function aTenantThatDeclaredColoursAloneShowsNothing(): void
    {
        // Given
        $brand = self::brand(new TenantLook(primaryColor: '#1b4b8f', primaryContentColor: '#ffffff'));

        // When / Then
        static::assertCount(0, $brand->filter('header[data-tenant="brand"]'));
    }

    /**
     * The page that says the row of the tenant is missing or disagrees with the configuration is a page
     * of this plane too, and it renders.
     */
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
        $loader->addPath(__DIR__ . '/../../../../src/symfony/templates', 'Beffroi');
        $twig = new Environment($loader);
        $twig->addFunction(new TwigFunction('beffroi_tenant', static fn (): ?TenantPresentation => $presentation));

        return new Crawler($twig->render('@Beffroi/_brand.html.twig'));
    }
}
