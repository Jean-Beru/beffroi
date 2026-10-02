<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\ChosenLocale;
use Beffroi\Bundle\Locale\ServedLocales;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;

/**
 * Issue #448: the language a visitor asked for is read on one cookie, and read back against the languages
 * this deployment serves, so that what somebody wrote by hand names a catalogue or names nothing.
 */
final class ChosenLocaleTest extends TestCase
{
    #[Test]
    #[DataProvider('provideCookies')]
    public function theChoiceIsReadBackAgainstWhatIsServed(?string $cookie, ?string $expected): void
    {
        // Given
        $chosen = new ChosenLocale(new ServedLocales(['en', 'fr'], 'en'));
        $request = Request::create('/login');
        if ($cookie !== null) {
            $request->cookies->set(ChosenLocale::COOKIE, $cookie);
        }

        // When / Then
        static::assertSame($expected, $chosen->current($request));
    }

    /**
     * @return iterable<string, array{string|null, string|null}>
     */
    public static function provideCookies(): iterable
    {
        yield 'none' => [null, null];
        yield 'empty' => ['', null];
        yield 'served' => ['fr', 'fr'];
        yield 'served, with a region' => ['fr-CA', 'fr'];
        yield 'not served' => ['de', null];
        yield 'not a language' => ['../etc/passwd', null];
    }

    #[Test]
    public function theCookieOfAChoiceIsNotReadableByAScriptAndStaysOnThisBrowser(): void
    {
        // Given
        $chosen = new ChosenLocale(new ServedLocales(['en', 'fr'], 'en'));

        // When
        $cookie = $chosen->cookie('fr');

        // Then
        static::assertSame(ChosenLocale::COOKIE, $cookie->getName());
        static::assertSame('fr', $cookie->getValue());
        static::assertTrue($cookie->isHttpOnly());
        static::assertTrue($cookie->isSecure());
        static::assertSame(Cookie::SAMESITE_LAX, $cookie->getSameSite());
        static::assertSame('/', $cookie->getPath());
    }
}
