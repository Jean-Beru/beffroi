<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Update\ThisBuild;
use function file_put_contents;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

/**
 * The release a build was compiled from, as the release workflow writes it.
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
}
