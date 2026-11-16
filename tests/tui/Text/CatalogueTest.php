<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Text;

use Beffroi\Tui\Text\Catalogue;
use Beffroi\Tui\Text\TerminalLocale;
use function array_keys;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sort;
use function sprintf;
use Symfony\Component\Translation\Loader\XliffFileLoader;
use Symfony\Component\Translation\MessageCatalogue;

/**
 * Every string the screen shows is in both languages.
 */
final class CatalogueTest extends TestCase
{
    #[Test]
    public function bothLanguagesHoldTheSameStrings(): void
    {
        // Given
        $loader = new XliffFileLoader();
        $domain = Catalogue::DOMAIN . MessageCatalogue::INTL_DOMAIN_SUFFIX;
        $identifiers = [];
        foreach (TerminalLocale::SUPPORTED as $locale) {
            $catalogue = $loader->load(sprintf('%s/%s.%s.xlf', Catalogue::directory(), $domain, $locale), $locale, $domain);
            $identifiers[$locale] = array_keys($catalogue->all($domain));
            sort($identifiers[$locale]);
        }

        // When / Then
        static::assertSame($identifiers['en'], $identifiers['fr']);
    }

    #[Test]
    public function aStringIsFormattedInTheLanguageOfTheTerminal(): void
    {
        // Given
        $translator = Catalogue::translator('fr');

        // When
        $line = $translator->trans(
            'session.expires_in',
            [
                'minutes' => 1,
                'time' => '2026-11-03 12:00:00 UTC',
            ],
            Catalogue::DOMAIN,
        );

        // Then
        static::assertSame('expire dans 1 minute (2026-11-03 12:00:00 UTC)', $line);
    }
}
