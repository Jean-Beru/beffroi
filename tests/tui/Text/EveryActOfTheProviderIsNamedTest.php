<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Text;

use Beffroi\Tui\Text\Catalogue;
use Beffroi\Tui\Text\TerminalLocale;
use function basename;
use function dirname;
use function file_get_contents;
use function glob;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function sprintf;

/**
 * The acts are read from the files of the events the packages declare, as text, so that the client reads none of their
 * code.
 */
final class EveryActOfTheProviderIsNamedTest extends TestCase
{
    private const string EVENTS = '/src/*/src/Domain/Event/*.php';

    #[Test]
    #[DataProvider('provideActsAndLanguages')]
    public function anActOfTheProviderIsNamedInTheLanguageOfTheTerminal(string $act, string $language): void
    {
        // Given
        $translator = Catalogue::translator($language);

        // When
        $named = $translator->trans('act.' . $act, [], Catalogue::DOMAIN);

        // Then
        static::assertNotSame('act.' . $act, $named);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideActsAndLanguages(): iterable
    {
        foreach (self::events() as $act) {
            if ($act === null) {
                continue;
            }
            foreach (TerminalLocale::SUPPORTED as $language) {
                yield sprintf('%s in %s', $act, $language) => [$act, $language];
            }
        }
    }

    #[Test]
    public function everyEventOfThePackagesNamesItsActWhereThisTestReadsIt(): void
    {
        // When
        $unnamed = [];
        foreach (self::events() as $event => $act) {
            if ($act === null) {
                $unnamed[] = $event;
            }
        }

        // Then
        static::assertSame([], $unnamed);
    }

    /**
     * @return array<string, ?string> the name of its act by event, null for an event whose name this test cannot read
     */
    private static function events(): array
    {
        $files = glob(dirname(__DIR__, 3) . self::EVENTS);
        if ($files === false || $files === []) {
            static::fail(sprintf('No event is declared under %s.', self::EVENTS));
        }
        $events = [];
        foreach ($files as $file) {
            $source = file_get_contents($file);
            if ($source === false) {
                static::fail(sprintf('The event %s cannot be read.', $file));
            }
            if (preg_match('/^(?:final |readonly |abstract )*class /m', $source) !== 1) {
                continue;
            }
            $events[basename(dirname($file, 4)) . '/' . basename($file, '.php')] = preg_match("/const string NAME = '([a-z_.]+)';/", $source, $matches) === 1
                ? $matches[1]
                : null;
        }

        return $events;
    }
}
