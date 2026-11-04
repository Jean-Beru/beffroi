<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Text;

use Beffroi\Tui\Text\TerminalColours;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * https://no-color.org: NO_COLOR set to anything but the empty string takes the colours away.
 */
final class TerminalColoursTest extends TestCase
{
    /**
     * @param array<string, string> $environment
     */
    #[Test]
    #[DataProvider('provideEnvironments')]
    public function colourIsAllowedUnlessNoColorIsSet(array $environment, bool $allowed): void
    {
        // When / Then
        static::assertSame($allowed, TerminalColours::allowed($environment));
    }

    /**
     * @return iterable<string, array{array<string, string>, bool}>
     */
    public static function provideEnvironments(): iterable
    {
        yield 'nothing set' => [[], true];
        yield 'NO_COLOR set to 1' => [['NO_COLOR' => '1'], false];
        yield 'NO_COLOR set to a word' => [['NO_COLOR' => 'yes'], false];
        yield 'NO_COLOR empty' => [['NO_COLOR' => ''], true];
    }
}
