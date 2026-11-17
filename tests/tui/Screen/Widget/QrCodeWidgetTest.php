<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Widget;

use function array_map;
use function array_slice;
use BaconQrCode\Common\ErrorCorrectionLevel;
use BaconQrCode\Encoder\ByteMatrix;
use BaconQrCode\Encoder\Encoder;
use Beffroi\Tui\Screen\Widget\QrCodeWidget;
use function count;
use function intdiv;
use function max;
use function mb_str_split;
use function mb_substr;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Tui\Ansi\AnsiUtils;
use Symfony\Component\Tui\Render\RenderContext;
use function trim;

/**
 * ISO/IEC 18004: a code is drawn whole in the room it is given, every module of its matrix in its place inside a quiet
 * zone, or the room it needs is said in its place.
 */
final class QrCodeWidgetTest extends TestCase
{
    private const string LINK = 'https://op.example/enrol/01a1e879-8c67-7d46-b8e8-b2a0285ee2a1/7Hk2mN9qR4sT6vW8xY0zA1bC3dE5fG7hJ9kL2mN4pQ6';

    #[Test]
    #[DataProvider('provideRoomsAndQuietZones')]
    public function everyModuleOfTheMatrixIsDrawnInItsPlaceInsideItsQuietZone(int $columns, int $rows, int $quiet): void
    {
        // Given
        $code = new QrCodeWidget()->setText(self::LINK);

        // When
        $lines = $code->render(new RenderContext($columns, $rows));

        // Then
        static::assertSame(self::modules(self::matrix(), $quiet), self::read($lines, $columns, self::matrix()->getWidth() + (2 * $quiet)));
    }

    /**
     * @return iterable<string, array{int, int, int}>
     */
    public static function provideRoomsAndQuietZones(): iterable
    {
        $size = self::matrix()->getWidth();
        yield 'room for a quiet zone of four modules' => [120, 40, 4];
        yield 'room for one of two modules only' => [$size + 4, intdiv($size + 5, 2), 2];
    }

    #[Test]
    #[DataProvider('provideRooms')]
    public function aCodeNeverDrawsPastTheRoomItIsGiven(int $columns, int $rows): void
    {
        // Given
        $code = new QrCodeWidget()
            ->setText(self::LINK)
            ->setTooSmall('The terminal is too small.');

        // When
        $lines = $code->render(new RenderContext($columns, $rows));

        // Then
        static::assertSame([true, true], [count($lines) <= $rows, max([0, ...array_map(AnsiUtils::visibleWidth(...), $lines)]) <= $columns]);
    }

    /**
     * @return iterable<string, array{int, int}>
     */
    public static function provideRooms(): iterable
    {
        yield 'a wide and tall room' => [200, 60];
        yield 'a terminal of 80 by 24' => [80, 24];
        yield 'a narrow one' => [30, 40];
        yield 'a low one' => [120, 10];
    }

    #[Test]
    public function aRoomTooSmallForTheCodeSaysSoInItsPlace(): void
    {
        // Given
        $code = new QrCodeWidget()
            ->setText(self::LINK)
            ->setTooSmall('The terminal is too small.');

        // When
        $lines = $code->render(new RenderContext(30, 40));

        // Then
        static::assertSame(['The terminal is too small.'], array_map(trim(...), $lines));
    }

    #[Test]
    public function theRoomItNeedsIsTheCodeInsideTheNarrowestQuietZone(): void
    {
        // Given
        $size = self::matrix()->getWidth();

        // When
        $room = new QrCodeWidget()
            ->setText(self::LINK)
            ->room();

        // Then
        static::assertSame([$size + 4, intdiv($size + 5, 2)], $room);
    }

    #[Test]
    public function aCodeForgottenDrawsNothing(): void
    {
        // Given
        $code = new QrCodeWidget()->setText(self::LINK);

        // When
        $lines = $code->forget()->render(new RenderContext(120, 40));

        // Then
        static::assertSame([], $lines);
    }

    private static function matrix(): ByteMatrix
    {
        return Encoder::encode(self::LINK, ErrorCorrectionLevel::M(), Encoder::DEFAULT_BYTE_MODE_ENCODING, null, false)->getMatrix();
    }

    /**
     * The modules of the matrix inside a quiet zone of that width, row by row, each dark one true.
     *
     * @return list<list<bool>>
     */
    private static function modules(ByteMatrix $matrix, int $quiet): array
    {
        $size = $matrix->getWidth();
        $rows = [];
        for ($row = -$quiet; $row < ($size + $quiet); ++$row) {
            $modules = [];
            for ($column = -$quiet; $column < ($size + $quiet); ++$column) {
                $modules[] = $column >= 0 && $row >= 0 && $column < $size && $row < $size && $matrix->get($column, $row) === 1;
            }
            $rows[] = $modules;
        }

        return $rows;
    }

    /**
     * The modules the lines draw, read back from their half blocks: the upper half the first row of a line, the lower
     * half the second.
     *
     * @param list<string> $lines
     *
     * @return list<list<bool>>
     */
    private static function read(array $lines, int $columns, int $modules): array
    {
        $margin = intdiv($columns - $modules, 2);
        $rows = [];
        foreach ($lines as $line) {
            $upper = [];
            $lower = [];
            foreach (mb_str_split(mb_substr($line, $margin, $modules)) as $block) {
                $upper[] = $block === '█' || $block === '▀';
                $lower[] = $block === '█' || $block === '▄';
            }
            $rows[] = $upper;
            $rows[] = $lower;
        }

        return array_slice($rows, 0, $modules);
    }
}
