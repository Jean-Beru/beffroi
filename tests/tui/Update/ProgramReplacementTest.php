<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Update\ProgramReplacement;
use Beffroi\Tui\Update\SelfUpdateException;
use Beffroi\Tui\Update\TemporaryDirectory;
use function chmod;
use function clearstatcache;
use function dirname;
use function file_get_contents;
use function file_put_contents;
use function fileperms;
use function is_file;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function scandir;
use function sprintf;

/**
 * The file of the program replaced by another written beside it.
 */
final class ProgramReplacementTest extends TestCase
{
    private TemporaryDirectory $directory;

    private string $program;

    protected function setUp(): void
    {
        $this->directory = TemporaryDirectory::create();
        $this->program = $this->directory->file('beffroi-tui');
        file_put_contents($this->program, 'the old program');
        chmod($this->program, 0o750);
    }

    protected function tearDown(): void
    {
        chmod($this->directory->path, 0o700);
        $this->directory->remove();
    }

    #[Test]
    public function theStagedFileIsBesideTheProgramAndReadableByThisUserAlone(): void
    {
        // When
        $staged = new ProgramReplacement()->stage($this->program);

        // Then
        static::assertSame([$this->directory->path, 0o600, ''], [dirname($staged), fileperms($staged) & 0o777, file_get_contents($staged)]);
    }

    #[Test]
    public function theStagedFileTakesThePlaceAndTheModeOfTheProgram(): void
    {
        // Given
        $replacement = new ProgramReplacement();
        $staged = $replacement->stage($this->program);
        file_put_contents($staged, 'the new program');

        // When
        $replacement->replace($this->program, $staged);

        // Then
        clearstatcache();
        static::assertSame(['the new program', 0o750, false], [file_get_contents($this->program), fileperms($this->program) & 0o777, is_file($staged)]);
    }

    #[Test]
    public function aDirectoryThisUserCannotWriteToIsRefused(): void
    {
        // Given
        chmod($this->directory->path, 0o500);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The directory %s is not writable by this user, and the update asks for no more privileges: nothing is replaced.',
            $this->directory->path,
        ));

        // When
        new ProgramReplacement()->stage($this->program);
    }

    #[Test]
    public function aDiscardedFileLeavesTheProgramAlone(): void
    {
        // Given
        $replacement = new ProgramReplacement();
        $staged = $replacement->stage($this->program);

        // When
        $replacement->discard($staged);

        // Then
        static::assertSame(['.', '..', 'beffroi-tui'], scandir($this->directory->path));
    }
}
