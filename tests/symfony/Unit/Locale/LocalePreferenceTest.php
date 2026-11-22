<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Locale;

use App\Locale\LocalePreference;
use App\Locale\ServedLocales;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

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
