<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Widget;

use Beffroi\Tui\Screen\Widget\NavigationWidget;
use function count;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function rtrim;
use function str_contains;
use Symfony\Component\Tui\Ansi\AnsiUtils;
use Symfony\Component\Tui\Render\RenderContext;

/**
 * The sections in a column on a wide terminal and in tabs on a narrow one, chosen by the arrows of either direction.
 */
final class NavigationWidgetTest extends TestCase
{
    #[Test]
    public function onAWideTerminalTheSectionsAreAColumnAsTallAsTheRoom(): void
    {
        // Given
        $navigation = self::navigation(120);

        // When
        $navigation->beforeRender();
        $lines = $navigation->render(new RenderContext(30, 10));

        // Then
        static::assertSame([10, ' Instance'], [count($lines), AnsiUtils::stripAnsiCodes(rtrim($lines[0]))]);
    }

    #[Test]
    public function onANarrowTerminalTheSectionsAreTabsAroundTheOneShown(): void
    {
        // Given
        $navigation = self::navigation(60);
        $navigation->show(3);

        // When
        $navigation->beforeRender();
        $lines = $navigation->render(new RenderContext(30, 10));

        // Then
        static::assertSame([1, true, true], [count($lines), str_contains($lines[0], 'Clients'), AnsiUtils::visibleWidth($lines[0]) <= 30]);
    }

    #[Test]
    public function theArrowsOfEitherDirectionChooseASection(): void
    {
        // Given
        $navigation = self::navigation(120);

        // When
        $navigation->handleInput("\e[C");
        $navigation->handleInput("\e[B");

        // Then
        static::assertSame(2, $navigation->shown());
    }

    private static function navigation(int $columns): NavigationWidget
    {
        return new NavigationWidget(90, static fn (): int => $columns)->setLabels([
            'Instance',
            'Session',
            'Tenant',
            'Clients',
            'Signing keys',
            'Users',
            'Monitoring',
        ]);
    }
}
