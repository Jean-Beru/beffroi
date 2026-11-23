<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen\Section;

use Beffroi\Tui\Tests\Fixture\FakeGitHub;
use Beffroi\Tui\Tests\Fixture\Programs;
use Beffroi\Tui\Tests\Fixture\SignedInScreen;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

/**
 * The instance, the client this program is there, and the build of this program, which the section shows first.
 */
final class InstanceSectionTest extends TestCase
{
    private ?SignedInScreen $screen = null;

    protected function tearDown(): void
    {
        $this->screen?->stop();
    }

    #[Test]
    public function theSectionNamesTheBuildOfThisProgram(): void
    {
        // When
        $this->screen = new SignedInScreen([]);

        // Then
        static::assertMatchesRegularExpression('/Version +beffroi-tui, from its sources/', $this->screen->screen());
    }

    #[Test]
    public function aBuildThatIsNoReleaseSaysNothingOfAnUpdate(): void
    {
        // When
        $this->screen = new SignedInScreen([]);

        // Then
        static::assertDoesNotMatchRegularExpression('/Update +/', $this->screen->screen());
    }

    #[Test]
    public function theSectionNamesTheNewerReleaseOfTheLineAndTheCommandThatInstallsIt(): void
    {
        // Given
        $program = Programs::release('0.1.0', FakeGitHub::serving('0.1.1', str_repeat('0', 64)));
        $program->lookForANewerRelease();

        // When
        $this->screen = new SignedInScreen([], program: $program);

        // Then
        static::assertMatchesRegularExpression('/Update +0\.1\.1 is out: beffroi-tui self-update/', $this->screen->screen());
    }
}
