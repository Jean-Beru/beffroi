<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Locale;

use App\Locale\Moments;
use App\Locale\UserTimeZone;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §5.7
 */
final class MomentsTest extends TestCase
{
    #[Test]
    #[DataProvider('provideLocales')]
    public function aMomentIsWrittenAsItsLanguageWritesIt(string $locale, string $expected): void
    {
        // Given
        $moments = new Moments(new UserTimeZone());

        // When
        $written = $moments->write(new DateTimeImmutable('2026-11-23T14:05:00+00:00'), null, $locale);

        // Then
        static::assertSame($expected, $written);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideLocales(): iterable
    {
        yield 'English, as British English writes it' => ['en', '23 Nov 2026, 14:05 UTC'];
        yield 'French' => ['fr', '23 nov. 2026, 14:05 UTC'];
        yield 'Portuguese, as Portugal writes it' => ['pt', '23/11/2026, 14:05 UTC'];
    }
}
