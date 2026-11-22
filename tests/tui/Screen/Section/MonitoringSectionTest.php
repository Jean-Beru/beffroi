<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_match;
use function str_contains;

/**
 * What the instance knows of itself now: the points `beffroi:doctor` looks at, then what it holds, counted when asked.
 */
final class MonitoringSectionTest extends TestCase
{
    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    public function eachPointLookedAtIsMarkedGreenOrRedWithWhatItFound(): void
    {
        // Given
        $this->screen = new SignedInScreen(self::answers());

        // When
        $this->screen->open('section.monitoring');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([1, 1, true], [
            preg_match('/■ ok +The lane of the notifications/', $screen),
            preg_match('/■ failed +The keys of the tenant/', $screen),
            str_contains($screen, 'The KMS does not open the active key.'),
        ]);
    }

    /**
     * A point that does not say it is green is red.
     */
    #[Test]
    public function aPointThatDoesNotSayItIsGreenIsRed(): void
    {
        // Given
        $answers = self::answers();
        $answers['/health'] = ['checks' => [['about' => 'A point that says nothing', 'lines' => []]]];
        $this->screen = new SignedInScreen($answers);

        // When
        $this->screen->open('section.monitoring');

        // Then
        static::assertMatchesRegularExpression('/■ failed +A point that says nothing/', $this->screen->screen());
    }

    /**
     * https://no-color.org aside, the square of a point that holds is lit in the signal of the brand, and the square of
     * one that does not in the red of the terminal until its background is known.
     */
    #[Test]
    public function withColoursTheMarksAreDrawnInTheirColour(): void
    {
        // Given
        $this->screen = new SignedInScreen(self::answers(), colours: true);

        // When
        $this->screen->open('section.monitoring');

        // Then
        $this->screen->screen();
        static::assertSame(
            [true, 1],
            [
                str_contains($this->screen->terminal->getOutput(), '38;2;198;244;50m■'),
                preg_match('/31m(?:\e\[[0-9;]*m)*■/', $this->screen->terminal->getOutput()),
            ],
        );
    }

    #[Test]
    public function theStatisticsCountWhatTheInstanceHolds(): void
    {
        // Given
        $this->screen = new SignedInScreen(self::answers());

        // When
        $this->screen->open('section.monitoring');

        // Then
        $screen = $this->screen->screen();
        static::assertSame([true, 1, 1, 1], [
            str_contains($screen, 'since 2026-05-08 10:00 UTC'),
            preg_match('/│ 3 +│/', $screen),
            preg_match('/│ open sessions +│/', $screen),
            preg_match('/failed sign-ins +[█▏▎▍▌▋▊▉]* *7/', $screen),
        ]);
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private static function answers(): array
    {
        return [
            '/health' => [
                'checks' => [
                    ['about' => 'The lane of the notifications', 'green' => true, 'lines' => ['3 messages wait, the oldest for 2 seconds.']],
                    [
                        'about' => 'The keys of the tenant',
                        'green' => false,
                        'lines' => ['The KMS does not open the active key.', 'Start the KMS, then look again.'],
                    ],
                ],
            ],
            '/statistics' => [
                'since' => '2026-05-08T10:00:00Z',
                'until' => '2026-11-04T10:00:00Z',
                'users' => 12,
                'clients' => 5,
                'open_sessions' => 3,
                'keys' => ['staged' => 1, 'active' => 1, 'retiring' => 0, 'retired' => 2],
                'acts' => [['act' => 'user.authenticated', 'count' => 40], ['act' => 'authentication.failed', 'count' => 7]],
                'queues' => [['transport' => 'async', 'messages' => 0]],
            ],
        ];
    }
}
