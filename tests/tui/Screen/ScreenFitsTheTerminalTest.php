<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen;

use function array_map;
use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use function explode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function range;
use function sprintf;
use function str_contains;

/**
 * The screen is as tall and as wide as the terminal and never more, whatever the section and whatever it read: a
 * screen that drew more rows than the terminal has would push its first rows out of sight, the header first, so the
 * header stays on the first row and the keys on the last.
 */
final class ScreenFitsTheTerminalTest extends TestCase
{
    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    #[DataProvider('provideSectionsAndTerminals')]
    public function theHeaderStaysOnTheFirstRowAndTheKeysOnTheLast(string $section, int $columns, int $rows): void
    {
        // Given
        $this->screen = new SignedInScreen(self::answers(), columns: $columns, rows: $rows);

        // When
        $this->screen->open($section);

        // Then
        $lines = explode("\n", $this->screen->screen());
        static::assertSame([true, true], [str_contains($lines[0], 'Administration'), str_contains($lines[$rows - 1], 'choose')]);
    }

    /**
     * @return iterable<string, array{string, int, int}>
     */
    public static function provideSectionsAndTerminals(): iterable
    {
        foreach ([
            'section.instance',
            'section.session',
            'section.tenant',
            'section.clients',
            'section.keys',
            'section.users',
            'section.monitoring',
        ] as $section) {
            foreach ([[60, 16], [84, 24], [120, 30], [200, 60]] as [$columns, $rows]) {
                yield sprintf('%s on %d by %d', $section, $columns, $rows) => [$section, $columns, $rows];
            }
        }
    }

    /**
     * What an instance with some history answers: more clients than a screen holds, keys in every state, a point of
     * its health that does not hold, and acts of many names.
     *
     * @return array<string, array<string, mixed>>
     */
    private static function answers(): array
    {
        return [
            '/tenant' => [
                'slug' => 'default',
                'issuer' => 'https://op.example',
                'name' => 'An instance whose name is longer than a narrow terminal is wide',
                'created_at' => '2026-10-01T08:00:00Z',
                'login_floor' => 'any_proof',
                'authentication_classes' => [['acr' => '1', 'predicate' => 'single_factor'], ['acr' => 'phr', 'predicate' => 'phishing_resistant']],
                'administrators' => ['administrators', 'operators', 'security officers'],
                'administration_api' => 'https://admin.op.example',
                'journal_retention_days' => 180,
            ],
            '/clients' => ['clients' => array_map(
                static fn (int $number): array => [
                    'client_id' => sprintf('client-%d-with-an-identifier-drawn-at-random', $number),
                    'client_name' => sprintf('Client number %d, registered by the conformance suite', $number),
                    'source' => 'registration',
                    'registered_at' => '2026-10-21T10:00:00Z',
                    'last_used_at' => null,
                ],
                range(1, 40),
            )],
            '/keys' => ['keys' => array_map(static fn (string $status): array => [
                'kid' => sprintf('k-2026-11-01-ES256-%s', $status),
                'algorithm' => 'ES256',
                'use' => 'sig',
                'status' => $status,
                'created_at' => '2026-11-01T00:00:00Z',
                'activation_due_at' => '2026-11-01T00:02:00Z',
                'activated_at' => '2026-11-01T00:02:00Z',
                'retiring_at' => null,
                'retirement_due_at' => null,
                'retired_at' => null,
                'past_its_age' => false,
            ], ['active', 'staged', 'retiring', 'retired'])],
            '/health' => [
                'checks' => [
                    [
                        'about' => 'The lane of the notifications tries a logout token again on the schedule the window assumes',
                        'green' => true,
                        'lines' => ['It tries six times over two hours.'],
                    ],
                    [
                        'about' => 'The KMS opens the active signing key',
                        'green' => false,
                        'lines' => ['Connection refused.', 'Nothing is signed until it opens.', 'Start the KMS, then look again.'],
                    ],
                ],
            ],
            '/statistics' => [
                'since' => '2026-05-08T10:00:00Z',
                'until' => '2026-11-04T10:00:00Z',
                'users' => 1200,
                'clients' => 40,
                'open_sessions' => 310,
                'keys' => ['staged' => 1, 'active' => 1, 'retiring' => 1, 'retired' => 1],
                'acts' => array_map(static fn (int $number): array => ['act' => sprintf('act.number_%d', $number), 'count' => $number * 17], range(1, 20)),
                'queues' => [['transport' => 'async', 'messages' => 4]],
            ],
        ];
    }
}
