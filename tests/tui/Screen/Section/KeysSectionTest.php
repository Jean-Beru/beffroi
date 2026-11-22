<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The signing keys of the tenant in their four states, as `beffroi:keys:list` says them.
 */
final class KeysSectionTest extends TestCase
{
    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    #[DataProvider('provideStates')]
    public function aKeyIsShownInItsState(string $status, string $shown): void
    {
        // Given
        $this->screen = new SignedInScreen(['/keys' => ['keys' => [self::key(['status' => $status])]]]);

        // When
        $this->screen->open('section.keys');

        // Then
        static::assertStringContainsString($shown, $this->screen->screen());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideStates(): iterable
    {
        yield 'staged, an empty square' => ['staged', '□ staged'];
        yield 'active, a full square' => ['active', '■ active'];
        yield 'retiring, a hatched square' => ['retiring', '▨ retiring'];
        yield 'retired, a dotted line' => ['retired', '┄ retired'];
        yield 'a state this program does not know, as the API wrote it' => ['revoked', '? revoked'];
    }

    #[Test]
    public function anActiveKeyPastItsAgeIsSaidSo(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/keys' => ['keys' => [self::key(['past_its_age' => true])]]]);

        // When
        $this->screen->open('section.keys');

        // Then
        static::assertStringContainsString('⚠ yes', $this->screen->screen());
    }

    #[Test]
    public function aTenantWithoutAKeyIsSaidToSignNothing(): void
    {
        // Given
        $this->screen = new SignedInScreen(['/keys' => ['keys' => []]]);

        // When
        $this->screen->open('section.keys');

        // Then
        static::assertStringContainsString('nothing can be signed', $this->screen->screen());
    }

    /**
     * @param array<string, mixed> $replacing
     *
     * @return array<string, mixed>
     */
    private static function key(array $replacing = []): array
    {
        return [
            ...[
                'kid' => 'kid-1',
                'algorithm' => 'ES256',
                'use' => 'sig',
                'status' => 'active',
                'created_at' => '2026-10-01T08:00:00Z',
                'activation_due_at' => '2026-10-02T08:00:00Z',
                'activated_at' => '2026-10-02T08:00:00Z',
                'retiring_at' => null,
                'retirement_due_at' => null,
                'retired_at' => null,
                'past_its_age' => false,
            ],
            ...$replacing,
        ];
    }
}
