<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Translation;

use function array_keys;
use function basename;
use function dirname;
use function glob;
use function is_string;
use MessageFormatter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function sprintf;
use Symfony\Component\Translation\Loader\XliffFileLoader;

/**
 * Architecture §5.7
 */
final class CataloguesTest extends TestCase
{
    private const string DOMAIN = 'beffroi+intl-icu';

    #[Test]
    #[DataProvider('provideLocales')]
    public function aCatalogueHoldsTheStringsOfTheEnglishOneAndNoOther(string $locale): void
    {
        // Given
        $english = array_keys(self::messages('en'));

        // When
        $theirs = array_keys(self::messages($locale));

        // Then
        static::assertSame($english, $theirs);
    }

    #[Test]
    #[DataProvider('provideLocales')]
    public function everyMessageOfACatalogueIsAnIcuMessageOfItsLanguage(string $locale): void
    {
        // Given
        $refused = [];

        // When
        foreach (self::messages($locale) as $key => $message) {
            if (MessageFormatter::create($locale, $message) === null) {
                $refused[] = $key;
            }
        }

        // Then
        static::assertSame([], $refused);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideLocales(): iterable
    {
        $paths = glob(self::path('*'));
        foreach ($paths === false ? [] : $paths as $path) {
            if (preg_match('/\.([a-z]{2,3}(?:_[A-Za-z]{2,4})*)\.xlf$/', basename($path), $match) === 1 && $match[1] !== 'en') {
                yield $match[1] => [$match[1]];
            }
        }
    }

    /**
     * @return array<string, string>
     */
    private static function messages(string $locale): array
    {
        $messages = [];
        foreach (new XliffFileLoader()->load(self::path($locale), $locale, self::DOMAIN)->all(self::DOMAIN) as $key => $message) {
            if (is_string($message)) {
                $messages[(string) $key] = $message;
            }
        }

        return $messages;
    }

    private static function path(string $locale): string
    {
        return sprintf('%s/apps/beffroi/translations/%s.%s.xlf', dirname(__DIR__, 4), self::DOMAIN, $locale);
    }
}
