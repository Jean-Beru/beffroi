<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Http;

use Beffroi\Bundle\Http\BrowserPreferences;
use Beffroi\Bundle\Locale\LocalePreference;
use Beffroi\Bundle\Locale\ServedLocales;
use Beffroi\Bundle\Tests\Fixture\APreference;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;

/**
 * Issue #573, architecture §5.7: the preferences of a browser travel on one cookie with a slot per
 * preference, read back through the preference that declared the slot. What the language serves is
 * LocalePreferenceTest, and what the choice of one does to the pages is LocaleChoiceTest.
 */
final class BrowserPreferencesTest extends TestCase
{
    #[Test]
    #[DataProvider('provideCookies')]
    public function aSlotIsReadBackThroughThePreferenceThatDeclaredIt(?string $cookie, ?string $expected): void
    {
        // Given
        $request = self::requestCarrying($cookie);

        // When / Then
        static::assertSame($expected, self::preferences()->read($request, LocalePreference::SLOT));
    }

    /**
     * @return iterable<string, array{string|null, string|null}>
     */
    public static function provideCookies(): iterable
    {
        yield 'no cookie' => [null, null];
        yield 'empty' => ['', null];
        yield 'the slot alone' => ['locale=fr', 'fr'];
        yield 'canonical, as the language is read' => ['locale=fr-CA', 'fr'];
        yield 'beside another slot' => ['theme=dark&locale=fr', 'fr'];
        yield 'a value nobody serves' => ['locale=de', null];
        yield 'another slot alone' => ['theme=dark', null];
        yield 'no value' => ['locale', null];
        yield 'written twice' => ['locale=fr&locale=en', 'en'];
        yield 'nothing a slot could be read from' => ['../etc/passwd', null];
    }

    #[Test]
    public function aSlotNoPreferenceDeclaresIsReadAsNothing(): void
    {
        // Given
        $request = self::requestCarrying('colour=red');

        // When / Then
        static::assertNull(self::preferences()->read($request, 'colour'));
    }

    /**
     * No script reads it (HttpOnly), it does not leave the requests of this browser (SameSite=Lax), the
     * issuer is served over TLS (Secure), and the "__Host-" prefix of the name is what has a browser check
     * those three, the path and the absence of a Domain rather than a reviewer.
     */
    #[Test]
    public function theCookieOfThePreferencesIsNotReadableByAScriptAndStaysOnThisBrowser(): void
    {
        // When
        $cookie = self::preferences()->cookie(self::requestCarrying(null), LocalePreference::SLOT, 'fr');

        // Then
        static::assertSame(BrowserPreferences::COOKIE, $cookie->getName());
        static::assertSame('locale=fr', $cookie->getValue());
        static::assertTrue($cookie->isHttpOnly());
        static::assertTrue($cookie->isSecure());
        static::assertSame(Cookie::SAMESITE_LAX, $cookie->getSameSite());
        static::assertSame('/', $cookie->getPath());
        static::assertNull($cookie->getDomain());
    }

    #[Test]
    public function writingOneSlotLeavesTheOthersAsTheyWere(): void
    {
        // Given
        $request = self::requestCarrying('locale=fr&theme=dark');

        // When
        $cookie = self::preferences()->cookie($request, 'theme', 'light');

        // Then
        static::assertSame('locale=fr&theme=light', $cookie->getValue());
    }

    /**
     * A slot the request carries and nobody serves is not carried over: the cookie that goes back holds
     * what this deployment has, so a value that stopped being served stops being written.
     */
    #[Test]
    public function writingOneSlotDropsWhatNobodyServes(): void
    {
        // Given
        $request = self::requestCarrying('locale=de&colour=red&theme=dark');

        // When
        $cookie = self::preferences()->cookie($request, 'theme', 'light');

        // Then
        static::assertSame('theme=light', $cookie->getValue());
    }

    #[Test]
    public function itRefusesToWriteASlotNoPreferenceDeclares(): void
    {
        // Given
        $request = self::requestCarrying(null);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('No preference of a browser declares the slot "colour"; the wired ones are "locale", "theme".');

        // When
        self::preferences()->cookie($request, 'colour', 'red');
    }

    #[Test]
    public function itRefusesToWriteAValueThePreferenceDoesNotServe(): void
    {
        // Given
        $request = self::requestCarrying(null);

        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('The preference of the slot "locale" does not serve the value "de".');

        // When
        self::preferences()->cookie($request, LocalePreference::SLOT, 'de');
    }

    #[Test]
    public function twoPreferencesOnOneSlotAreAFaultOfTheWiring(): void
    {
        // Then
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageIs('Two preferences of a browser name the slot "theme".');

        // When
        new BrowserPreferences([new APreference('theme', ['dark']), new APreference('theme', ['light'])]);
    }

    private static function preferences(): BrowserPreferences
    {
        return new BrowserPreferences([
            new LocalePreference(new ServedLocales(['en', 'fr'], 'en')),
            new APreference('theme', ['light', 'dark']),
        ]);
    }

    private static function requestCarrying(?string $cookie): Request
    {
        $request = Request::create('/login');
        if ($cookie !== null) {
            $request->cookies->set(BrowserPreferences::COOKIE, $cookie);
        }

        return $request;
    }
}
