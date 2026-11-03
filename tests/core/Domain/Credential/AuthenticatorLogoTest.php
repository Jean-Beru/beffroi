<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Credential;

use Beffroi\Core\Domain\Credential\AuthenticatorLogo;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\AuthenticatorImages;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The logo of a model of authenticator: an image of a data: URL (RFC 2397), which a page shows without fetching
 * anything, one for a light page and one for a dark page.
 */
final class AuthenticatorLogoTest extends TestCase
{
    #[Test]
    #[DataProvider('provideImages')]
    public function anImageOfADataUrlIsALogo(string $light, string $dark): void
    {
        // When
        $logo = new AuthenticatorLogo($light, $dark);

        // Then
        static::assertSame([$light, $dark], [$logo->light, $logo->dark]);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideImages(): iterable
    {
        yield 'a PNG, as the FIDO metadata carry one' => [AuthenticatorImages::PNG, AuthenticatorImages::PNG];
        yield 'an SVG for each theme, as the list of the community carries them' => [AuthenticatorImages::SVG_LIGHT, AuthenticatorImages::SVG_DARK];
    }

    #[Test]
    #[DataProvider('provideImagesThatAreNotOfADataUrl')]
    public function anImageThatIsNotAnImageOfADataUrlIsRefused(string $light, string $dark): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The logo of an authenticator is a PNG or an SVG image in a base64 data: URL (RFC 2397).');

        // When
        new AuthenticatorLogo($light, $dark);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideImagesThatAreNotOfADataUrl(): iterable
    {
        yield 'an image of the web for a light page' => ['https://example.com/logo.png', AuthenticatorImages::PNG];
        yield 'an image of the web for a dark page' => [AuthenticatorImages::PNG, 'https://example.com/logo.png'];
        yield 'a script' => ['javascript:alert(1)', AuthenticatorImages::PNG];
        yield 'a document' => ['data:text/html;base64,PHA+PC9wPg==', AuthenticatorImages::PNG];
        yield 'an image of another type' => ['data:image/gif;base64,R0lGODlhAQABAAAAACw=', AuthenticatorImages::PNG];
        yield 'an SVG that is not in base64' => ['data:image/svg+xml;utf8,<svg/>', AuthenticatorImages::PNG];
        yield 'an image whose base64 breaks off' => ['data:image/png;base64,iVBOR w0K', AuthenticatorImages::PNG];
        yield 'an image followed by a line' => [AuthenticatorImages::PNG . "\n", AuthenticatorImages::PNG];
        yield 'nothing' => ['', AuthenticatorImages::PNG];
    }

    #[Test]
    public function aSingleImageIsTheLogoOfBothThemes(): void
    {
        // When
        $logo = AuthenticatorLogo::single(AuthenticatorImages::PNG);

        // Then
        static::assertSame([AuthenticatorImages::PNG, AuthenticatorImages::PNG], [$logo->light, $logo->dark]);
        static::assertFalse($logo->hasDarkVariant());
    }

    #[Test]
    public function anotherImageForADarkPageIsADarkVariant(): void
    {
        // When / Then
        static::assertTrue(new AuthenticatorLogo(AuthenticatorImages::SVG_LIGHT, AuthenticatorImages::SVG_DARK)->hasDarkVariant());
    }
}
