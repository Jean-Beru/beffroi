<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Locale;

use App\Locale\ServedLocales;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §5.7, RFC 5646 §2.1, §2.2
 */
final class ServedLocalesTest extends TestCase
{
    #[Test]
    public function theLocalesAreCanonicalAndTheDefaultComesFirst(): void
    {
        // Given
        $served = new ServedLocales(['en', 'fr-ca', 'FR', 'zh-hant'], 'fr');

        // When / Then
        static::assertSame(['fr', 'en', 'fr_CA', 'zh_Hant'], $served->all);
    }

    #[Test]
    public function theDefaultLocaleIsCanonical(): void
    {
        // When / Then
        static::assertSame('fr_CA', new ServedLocales(['en'], 'fr-ca')->default);
    }

    /**
     * @param list<string> $enabled
     * @param list<string> $tags
     */
    #[Test]
    #[DataProvider('provideReadings')]
    public function aTagIsReadAgainstTheLocalesThisDeploymentHas(array $enabled, array $tags, ?string $expected): void
    {
        // Given
        $served = new ServedLocales($enabled, 'en');

        // When / Then
        static::assertSame($expected, $served->match($tags));
    }

    /**
     * @return iterable<string, array{list<string>, list<string>, string|null}>
     */
    public static function provideReadings(): iterable
    {
        yield 'the first tag a served locale matches wins' => [['en', 'fr'], ['de', 'fr-CA', 'en'], 'fr'];
        yield 'a region is kept when that locale is served' => [['en', 'fr', 'fr_CA'], ['fr-ca'], 'fr_CA'];
        yield 'a region is dropped when only the language is served' => [['en', 'fr'], ['fr-BE'], 'fr'];
        yield 'a script subtag is matched before the language alone' => [['en', 'zh_Hant'], ['zh-Hant-TW'], 'zh_Hant'];
        yield 'a tag no locale matches is skipped, not refused' => [['en', 'fr'], ['xx-YY', 'fr'], 'fr'];
        yield 'a private use subtag is ignored' => [['en', 'fr'], ['fr-x-private'], 'fr'];
        yield 'a region the extended language subtags and the script are not before is not read' => [
            ['en', 'fr', 'fr_CA'],
            ['fr-abc-def-ghi-Latn-1694acad-CA'],
            'fr',
        ];
        yield 'a tag that names no language is ignored' => [['en', 'fr'], ['', '1-2', 'fr'], 'fr'];
        yield 'no tag matches anything' => [['en', 'fr'], ['de', 'es'], null];
        yield 'nothing is asked' => [['en', 'fr'], [], null];
    }
}
