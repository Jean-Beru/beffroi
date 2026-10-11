<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Locale;

use Beffroi\Bundle\Locale\LocalePreference;
use Beffroi\Bundle\Locale\ServedLocales;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #448: the language a visitor asked for is read back against the languages this deployment serves,
 * so that what somebody wrote by hand on the cookie of the preferences names a catalogue or names nothing.
 * Where that slot lives and what the cookie does with it is BrowserPreferencesTest.
 */
final class LocalePreferenceTest extends TestCase
{
    #[Test]
    #[DataProvider('provideValues')]
    public function theChoiceIsReadBackAgainstWhatIsServed(string $value, ?string $expected): void
    {
        // Given
        $preference = new LocalePreference(new ServedLocales(['en', 'fr'], 'en'));

        // When / Then
        static::assertSame($expected, $preference->read($value));
    }

    /**
     * @return iterable<string, array{string, string|null}>
     */
    public static function provideValues(): iterable
    {
        yield 'empty' => ['', null];
        yield 'served' => ['fr', 'fr'];
        yield 'served, with a region' => ['fr-CA', 'fr'];
        yield 'not served' => ['de', null];
        yield 'not a language' => ['../etc/passwd', null];
    }
}
