<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Widget;

use function array_map;
use Beffroi\Tui\Screen\Widget\ChartBar;
use Beffroi\Tui\Screen\Widget\ChartWidget;
use Beffroi\Tui\Screen\Widget\Check;
use Beffroi\Tui\Screen\Widget\ChecksWidget;
use Beffroi\Tui\Screen\Widget\Tile;
use Beffroi\Tui\Screen\Widget\TilesWidget;
use function count;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function str_contains;
use Symfony\Component\Tui\Ansi\AnsiUtils;
use Symfony\Component\Tui\Render\RenderContext;

/**
 * The figures, the health and the acts of the instance in the room the screen gives them.
 */
final class MonitoringWidgetsTest extends TestCase
{
    #[Test]
    public function figuresAreBoxedWhenAThirdOfTheHeightHoldsTheBoxes(): void
    {
        // Given
        $tiles = new TilesWidget()->setTiles([new Tile('12', 'people'), new Tile('3', 'open sessions')]);

        // When
        $lines = $tiles->render(new RenderContext(80, 30));

        // Then
        static::assertSame([4, true], [count($lines), str_contains($lines[0], '┌')]);
    }

    #[Test]
    public function figuresAreWrittenOnALineWhenTheBoxesDoNotFit(): void
    {
        // Given
        $tiles = new TilesWidget()->setTiles([new Tile('12', 'people'), new Tile('3', 'open sessions')]);

        // When
        $lines = $tiles->render(new RenderContext(80, 6));

        // Then
        static::assertSame(['12 people   3 open sessions'], array_map(AnsiUtils::stripAnsiCodes(...), $lines));
    }

    #[Test]
    public function theBarsThatDoNotFitAreCounted(): void
    {
        // Given
        $chart = new ChartWidget()->setBars(array_map(static fn (int $count): ChartBar => new ChartBar('act', $count), range(1, 10)), 'none', '%d more');

        // When
        $lines = $chart->render(new RenderContext(60, 4));

        // Then
        static::assertSame([4, '7 more'], [count($lines), AnsiUtils::stripAnsiCodes($lines[3])]);
    }

    #[Test]
    public function theLargestCountFillsTheBar(): void
    {
        // Given
        $chart = new ChartWidget()->setBars([new ChartBar('sign-ins', 40), new ChartBar('failed', 7, true)], 'none');

        // When
        $lines = array_map(AnsiUtils::stripAnsiCodes(...), $chart->render(new RenderContext(40, 4)));

        // Then
        static::assertSame('sign-ins  ██████████████████████████  40', $lines[0]);
    }

    #[Test]
    public function aPointThatDoesNotHoldHasItsFindingsShownFirst(): void
    {
        // Given
        $checks = new ChecksWidget()->setChecks(
            [
                new Check(true, 'The lane', ['It tries six times.']),
                new Check(false, 'The keys', ['The KMS does not open the key.']),
            ],
            'ok',
            'failed',
            'nothing',
        );

        // When
        $lines = array_map(AnsiUtils::stripAnsiCodes(...), $checks->render(new RenderContext(60, 3)));

        // Then
        static::assertSame(['■ ok      The lane', '■ failed  The keys', '          The KMS does not open the key.'], $lines);
    }
}
