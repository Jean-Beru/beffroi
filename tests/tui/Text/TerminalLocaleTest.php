<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Text;

use Beffroi\Tui\Text\TerminalLocale;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The language of the terminal is the first of LC_ALL, LC_MESSAGES and LANG that is set, as POSIX reads them.
 */
final class TerminalLocaleTest extends TestCase
{
    /**
     * @param array<string, string> $environment
     */
    #[Test]
    #[DataProvider('provideEnvironments')]
    public function theLanguageIsTheOneOfTheFirstVariableSet(array $environment, string $language): void
    {
        // When / Then
        static::assertSame($language, TerminalLocale::of($environment));
    }

    /**
     * @return iterable<string, array{array<string, string>, string}>
     */
    public static function provideEnvironments(): iterable
    {
        yield 'LC_ALL first' => [['LC_ALL' => 'fr_FR.UTF-8', 'LANG' => 'en_GB.UTF-8'], 'fr'];
        yield 'LC_MESSAGES before LANG' => [['LC_MESSAGES' => 'fr_CA', 'LANG' => 'en_US.UTF-8'], 'fr'];
        yield 'an empty variable is not set' => [['LC_ALL' => '', 'LANG' => 'fr_BE@euro'], 'fr'];
        yield 'LANG alone' => [['LANG' => 'en_US.UTF-8'], 'en'];
        yield 'the C locale' => [['LANG' => 'C.UTF-8'], 'en'];
        yield 'a language the catalogue does not hold' => [['LANG' => 'de_DE.UTF-8'], 'en'];
        yield 'nothing set' => [[], 'en'];
    }
}
