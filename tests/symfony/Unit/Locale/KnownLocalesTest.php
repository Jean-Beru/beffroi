<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Locale;

use Beffroi\Bundle\Locale\KnownLocales;
use function array_keys;
use function array_slice;
use function count;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function asort;
use const SORT_STRING;

/**
 * Issue #479: the languages a person may say they read, which are the locales ICU has data for. Not the
 * ones this deployment serves: "locale" is a claim of OIDC Core §5.1 and not a setting of this provider.
 */
final class KnownLocalesTest extends TestCase
{
    #[Test]
    #[DataProvider('provideLanguages')]
    public function aLanguageIsKnownUnderItsOwnName(string $tag, string $name): void
    {
        // When / Then
        static::assertSame($name, new KnownLocales()->all[$tag] ?? null);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideLanguages(): iterable
    {
        yield 'french' => ['fr', 'français'];
        yield 'japanese' => ['ja', '日本語'];
        yield 'arabic' => ['ar', 'العربية'];
        yield 'brazilian portuguese' => ['pt-BR', 'português (Brasil)'];
    }

    /**
     * The shape the claim is defined in and the shape a browser sends, where ICU writes a tag with
     * underscores.
     */
    #[Test]
    public function aTagIsCanonicalBcp47(): void
    {
        // When
        $tags = array_keys(new KnownLocales()->all);

        // Then
        foreach ($tags as $tag) {
            static::assertStringNotContainsString('_', $tag, $tag);
        }
    }

    /**
     * Several hundred, which is what makes the field a picker rather than a list.
     */
    #[Test]
    public function theLanguagesAreTheOnesIcuHasDataFor(): void
    {
        // When / Then
        static::assertGreaterThan(400, count(new KnownLocales()->all));
    }

    /**
     * Sorted by the name a person reads, so a list reads in the alphabet of whoever is looking rather
     * than in the order ICU keeps its data.
     */
    #[Test]
    public function theLanguagesAreSortedByTheNameAPersonReads(): void
    {
        // When
        $names = new KnownLocales()->all;

        // Then
        $sorted = $names;
        asort($sorted, SORT_STRING);
        static::assertSame(array_slice($sorted, 0, 5, true), array_slice($names, 0, 5, true));
    }
}
