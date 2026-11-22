<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Update\ReleaseVersion;
use Beffroi\Tui\Update\RunningProgram;
use Beffroi\Tui\Update\SelfUpdateException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What runs, and the file of a release that takes its place.
 */
final class RunningProgramTest extends TestCase
{
    #[Test]
    public function aPharRunByPhpIsReplacedByThePharOfTheRelease(): void
    {
        // Given
        $program = new RunningProgram('cli', '/usr/local/bin/beffroi-tui', 'Linux', 'x86_64', ReleaseVersion::fromTag('0.0.1'));

        // When / Then
        static::assertSame(['/usr/local/bin/beffroi-tui', 'beffroi-tui.phar'], [$program->path(), $program->asset()]);
    }

    #[Test]
    #[DataProvider('providePlatforms')]
    public function anExecutableIsReplacedByTheExecutableOfItsPlatform(string $system, string $machine, string $asset): void
    {
        // Given
        $program = new RunningProgram('micro', '/home/me/bin/beffroi-tui', $system, $machine, ReleaseVersion::fromTag('0.0.1'));

        // When / Then
        static::assertSame($asset, $program->asset());
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function providePlatforms(): iterable
    {
        yield 'Linux x86_64' => ['Linux', 'x86_64', 'beffroi-tui-linux-x86_64'];
        yield 'Linux arm64' => ['Linux', 'aarch64', 'beffroi-tui-linux-aarch64'];
        yield 'macOS on Apple silicon' => ['Darwin', 'arm64', 'beffroi-tui-macos-aarch64'];
    }

    #[Test]
    #[DataProvider('providePlatformsWithoutExecutable')]
    public function anExecutableOfAPlatformNoReleaseIsBuiltForIsRefused(string $system, string $machine, string $message): void
    {
        // Given
        $program = new RunningProgram('micro', '/home/me/bin/beffroi-tui', $system, $machine, ReleaseVersion::fromTag('0.0.1'));

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs($message);

        // When
        $program->asset();
    }

    /**
     * @return iterable<string, array{string, string, string}>
     */
    public static function providePlatformsWithoutExecutable(): iterable
    {
        yield 'macOS on Intel' => ['Darwin', 'x86_64', 'No release carries an executable for Darwin on x86_64.'];
        yield 'FreeBSD' => ['BSD', 'amd64', 'No release carries an executable for BSD on amd64.'];
    }

    #[Test]
    public function aProgramThatRunsFromItsSourcesIsRefused(): void
    {
        // Given
        $program = new RunningProgram('cli', '', 'Linux', 'x86_64', null);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('This program runs from its sources, as Composer installs it: Composer updates it.');

        // When
        $program->path();
    }

    #[Test]
    public function aBuildNotCompiledFromAReleaseIsRefused(): void
    {
        // Given
        $program = new RunningProgram('cli', '/tmp/beffroi-tui.phar', 'Linux', 'x86_64', null);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('This build of the program was not compiled from a release, and only a release replaces itself.');

        // When
        $program->release();
    }

    #[Test]
    public function theProgramOfThisSuiteRunsFromItsSources(): void
    {
        // When / Then
        static::assertSame(['', null], [RunningProgram::current()->archive, RunningProgram::current()->version]);
    }
}
