<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Widget;

use function array_map;
use Beffroi\Tui\Screen\Widget\Definition;
use Beffroi\Tui\Screen\Widget\DefinitionsWidget;
use function count;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function sprintf;
use function str_contains;
use Symfony\Component\Tui\Ansi\AnsiUtils;
use Symfony\Component\Tui\Render\RenderContext;

/**
 * Labels and values in the room they are given: a long value folded onto the lines the height spares, two columns when
 * they do not fit the height and the width allows it, and how many were left out otherwise.
 */
final class DefinitionsWidgetTest extends TestCase
{
    #[Test]
    public function aValueTooWideIsFoldedOntoTheLinesTheHeightSpares(): void
    {
        // Given
        $definitions = new DefinitionsWidget()->setDefinitions([new Definition('Address', 'one two three four five six')]);

        // When
        $lines = array_map(AnsiUtils::stripAnsiCodes(...), $definitions->render(new RenderContext(20, 5)));

        // Then
        static::assertSame(['Address  one two', '         three four', '         five six'], $lines);
    }

    #[Test]
    public function aValueTheHeightCannotFoldIsCut(): void
    {
        // Given
        $definitions = new DefinitionsWidget()->setDefinitions([new Definition('Address', 'one two three four five six')]);

        // When
        $lines = array_map(AnsiUtils::stripAnsiCodes(...), $definitions->render(new RenderContext(20, 1)));

        // Then
        static::assertSame(['Address  one two th…'], $lines);
    }

    #[Test]
    public function definitionsTallerThanTheRoomSitInTwoColumnsWhenTheWidthAllows(): void
    {
        // Given
        $definitions = new DefinitionsWidget()->setDefinitions(self::numbered(8));

        // When
        $lines = $definitions->render(new RenderContext(100, 4));

        // Then
        static::assertSame([4, true], [count($lines), str_contains($lines[0], '│')]);
    }

    #[Test]
    public function definitionsLeftOutAreCounted(): void
    {
        // Given
        $definitions = new DefinitionsWidget()->setDefinitions(self::numbered(8), '%d more');

        // When
        $lines = $definitions->render(new RenderContext(40, 4));

        // Then
        static::assertSame([4, '5 more'], [count($lines), AnsiUtils::stripAnsiCodes($lines[3])]);
    }

    /**
     * @return list<Definition>
     */
    private static function numbered(int $count): array
    {
        return array_map(static fn (int $number): Definition => new Definition(sprintf('Label %d', $number), sprintf('value %d', $number)), range(1, $count));
    }
}
