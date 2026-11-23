<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Update\ThisBuild;
use function file_put_contents;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function str_repeat;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

/**
 * The release a build was compiled from, or the name of a build of another ref, as the release workflow writes it.
 */
final class ThisBuildTest extends TestCase
{
    private string $file;

    protected function setUp(): void
    {
        $this->file = sprintf('%s/beffroi-tui-release-%s', sys_get_temp_dir(), uniqid());
    }

    protected function tearDown(): void
    {
        @unlink($this->file);
    }

    #[Test]
    public function theTagTheWorkflowWroteIsTheVersionOfTheBuild(): void
    {
        // Given
        file_put_contents($this->file, "0.0.1\n");

        // When
        $version = ThisBuild::versionIn($this->file);

        // Then
        static::assertSame('0.0.1', $version?->tag);
    }

    #[Test]
    public function aBuildWithoutTheFileCarriesNoVersion(): void
    {
        // When / Then
        static::assertNull(ThisBuild::versionIn($this->file));
    }

    #[Test]
    #[DataProvider('provideWhatIsNoTag')]
    public function aFileThatHoldsNoReleaseTagGivesNoVersion(string $content): void
    {
        // Given
        file_put_contents($this->file, $content);

        // When / Then
        static::assertNull(ThisBuild::versionIn($this->file));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoTag(): iterable
    {
        yield 'empty' => [''];
        yield 'a branch' => ['0.0.x'];
        yield 'a commit' => ['dcc0165f'];
    }

    #[Test]
    public function theSourcesCarryNoVersion(): void
    {
        // When / Then
        static::assertNull(ThisBuild::version());
    }

    #[Test]
    #[DataProvider('provideNames')]
    public function theNameTheWorkflowWroteIsTheNameOfTheBuild(string $name): void
    {
        // Given
        file_put_contents($this->file, $name . "\n");

        // When
        $build = ThisBuild::buildIn($this->file);

        // Then
        static::assertSame($name, $build);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNames(): iterable
    {
        yield 'a maintenance branch' => ['0.1.x-84491c5'];
        yield 'a branch of an issue' => ['feat/1134-the-screen-says-its-version-84491c5'];
        yield 'the longest' => [str_repeat('a', 200)];
    }

    #[Test]
    #[DataProvider('provideWhatIsNoName')]
    public function aFileThatHoldsNoNameOfABuildGivesNone(string $content): void
    {
        // Given
        file_put_contents($this->file, $content);

        // When / Then
        static::assertNull(ThisBuild::buildIn($this->file));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNoName(): iterable
    {
        yield 'empty' => [''];
        yield 'two lines' => ["0.1.x-84491c5\n0.1.x-63aafe9"];
        yield 'an escape sequence' => ["0.1.x-84491c5\e]0;title\x07"];
        yield 'a space' => ['0.1.x 84491c5'];
        yield 'an option' => ['--help'];
        yield 'too long' => [str_repeat('a', 201)];
    }

    #[Test]
    public function theSourcesCarryNoNameOfABuild(): void
    {
        // When / Then
        static::assertNull(ThisBuild::build());
    }
}
