<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\LocalesSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Architecture §5.7
 */
final class LocalesSectionTest extends TestCase
{
    #[Test]
    public function noLocaleNamedServesEveryCatalogueTheDefaultFirst(): void
    {
        // When
        $served = LocalesSection::served(['en', 'fr', 'de'], 'fr', []);

        // Then
        static::assertSame(['fr', 'en', 'de'], $served->all);
    }

    #[Test]
    public function theLocalesNamedAreTheOnesServedTheDefaultFirst(): void
    {
        // When
        $served = LocalesSection::served(['en', 'fr', 'de'], 'de', ['fr', 'de']);

        // Then
        static::assertSame(['de', 'fr'], $served->all);
    }

    /**
     * @param list<mixed> $chosen
     */
    #[Test]
    #[DataProvider('provideRefusedLists')]
    public function aListTheCataloguesCannotServeIsRefused(array $chosen, string $message): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs($message);

        // When
        LocalesSection::served(['en', 'fr'], 'en', $chosen);
    }

    /**
     * @return iterable<string, array{list<mixed>, string}>
     */
    public static function provideRefusedLists(): iterable
    {
        yield 'a language without a catalogue' => [
            ['en', 'sv'],
            'The "beffroi" configuration key "locales" names "sv", which no catalogue of the application holds; it has "en", "fr".',
        ];
        yield 'the default left out' => [
            ['fr'],
            'The "beffroi" configuration key "locales" leaves out the default locale "en": name it, or set the default locale to one of "fr".',
        ];
        yield 'an entry that is no string' => [
            ['en', 7],
            'The "beffroi" configuration key "locales" must be a list of strings.',
        ];
    }
}
