<?php

declare(strict_types=1);

namespace App\Tests\Functional;

use Beffroi\Bundle\Http\BrowserPreferences;
use function array_map;
use function array_values;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #573, architecture §5.7 and §6: the preferences of a browser travel on one cookie with a slot per
 * preference, the bundle owning the cookie and this application declaring the slot of the theme
 * (App\Theme\ThemePreference). What one slot holds is judged by the suite of the bundle; what is here is
 * what only this kernel can answer, two slots being declared on it and one on that one: that each form
 * writes its own and leaves the other as it was.
 */
final class BrowserPreferencesTest extends BrowserTestCase
{
    #[Test]
    public function theFormOfTheThemeLeavesTheLanguageAsItWas(): void
    {
        // Given
        $this->chooseTheLanguage('fr');

        // When
        $this->browser->request('POST', '/theme', ['theme' => 'dark']);

        // Then
        static::assertSame('locale=fr&theme=dark', $this->preferences());
    }

    #[Test]
    public function theFormOfTheLanguageLeavesTheThemeAsItWas(): void
    {
        // Given
        $this->browser->request('POST', '/theme', ['theme' => 'dark']);

        // When
        $this->chooseTheLanguage('fr');

        // Then
        static::assertSame('locale=fr&theme=dark', $this->preferences());
    }

    /**
     * The slot is read where the page is rendered and not in a script, so the document carries the theme it
     * was asked for and never shows the other one first (App\Twig\ThemeExtension).
     */
    #[Test]
    public function thePagesAreRenderedInTheThemeTheSlotNames(): void
    {
        // Given
        $this->browser->request('POST', '/theme', ['theme' => 'dark']);

        // When
        $page = $this->loginPage();

        // Then
        static::assertSame(['dark'], $page->filter('html')->extract(['data-theme']));
    }

    /**
     * The session of the browser and the preferences of the browser, and no third cookie: a preference
     * added beside these two is a slot of the second and never a cookie of its own.
     */
    #[Test]
    public function aPageAndItsFormsSetTheSessionOfTheBrowserAndThePreferencesOfTheBrowserAndNothingElse(): void
    {
        // When
        $this->loginPage();
        $ofThePage = self::namesOf($this->browser->getResponse());
        $this->browser->request('POST', '/theme', ['theme' => 'dark']);

        // Then
        // the name the mock file storage of the test environment gives the session; a deployment names it
        // "__Host-beffroi_session" (config/packages/framework.yaml), which SecurityHeadersTest reads
        static::assertSame(['MOCKSESSID'], $ofThePage);
        static::assertSame([BrowserPreferences::COOKIE], self::namesOf($this->browser->getResponse()));
    }

    private function loginPage(): Crawler
    {
        return $this->browser->request('GET', '/login');
    }

    /**
     * The language asked for through the form the bundle serves, drawn by this application: a token of its
     * own and the page to come back to, which is how a visitor asks.
     */
    private function chooseTheLanguage(string $locale): void
    {
        $token = self::string($this->loginPage()->filter('form[data-locale="choice"] input[name="_token"]')->attr('value'));
        $this->browser->request('POST', '/locale', ['_token' => $token, 'locale' => $locale, 'target' => '/login']);
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * What the last response wrote on the cookie of the preferences, whole: a response of either form
     * rewrites every slot, so what it did not name is what it read back off the request.
     */
    private function preferences(): string
    {
        foreach ($this->browser->getResponse()->headers->getCookies() as $cookie) {
            if ($cookie->getName() === BrowserPreferences::COOKIE) {
                return $cookie->getValue() ?? '';
            }
        }

        static::fail('The answer carries no cookie of the preferences of a browser.');
    }

    /**
     * @return list<string>
     */
    private static function namesOf(Response $response): array
    {
        return array_values(array_map(static fn (Cookie $cookie): string => $cookie->getName(), $response->headers->getCookies()));
    }
}
