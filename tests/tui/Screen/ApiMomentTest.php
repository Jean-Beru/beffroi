<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen;

use Beffroi\Tui\Screen\ApiMoment;
use Closure;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ApiMomentTest extends TestCase
{
    /**
     * A value the API wrote in no form of RFC 3339 §5.6 reaches the terminal as text, its escape sequences left out.
     *
     * @param Closure(?string): string $shown
     */
    #[Test]
    #[DataProvider('provideWaysOfShowingAnInstant')]
    public function aValueThatIsNoInstantIsShownAsText(Closure $shown): void
    {
        // When
        $text = $shown("2026-11-04\e[2J\e]0;title\x07");

        // Then
        static::assertStringNotContainsString("\e", $text);
    }

    /**
     * @return iterable<string, array{Closure(?string): string}>
     */
    public static function provideWaysOfShowingAnInstant(): iterable
    {
        yield 'in a definition' => [ApiMoment::of(...)];
        yield 'in a cell of a table' => [ApiMoment::short(...)];
    }
}
