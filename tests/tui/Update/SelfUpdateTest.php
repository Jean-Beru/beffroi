<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Tests\Fixture\FakeGitHub;
use Beffroi\Tui\Tests\Fixture\FakeSignature;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use Beffroi\Tui\Update\AssetDownload;
use Beffroi\Tui\Update\GitHubReleases;
use Beffroi\Tui\Update\ProgramReplacement;
use Beffroi\Tui\Update\ReleaseVersion;
use Beffroi\Tui\Update\RunningProgram;
use Beffroi\Tui\Update\SelfUpdate;
use Beffroi\Tui\Update\SelfUpdateException;
use Beffroi\Tui\Update\SignatureVerifierInterface;
use Beffroi\Tui\Update\TemporaryDirectory;
use function array_column;
use function count;
use function file_get_contents;
use function file_put_contents;
use function hash;
use function in_array;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function scandir;

/**
 * The program replaced by the newest release of its line, and left as it was whenever something does not hold.
 */
final class SelfUpdateTest extends TestCase
{
    private TemporaryDirectory $directory;

    private string $program;

    protected function setUp(): void
    {
        $this->directory = TemporaryDirectory::create();
        $this->program = $this->directory->file('beffroi-tui');
        file_put_contents($this->program, 'the old program');
    }

    protected function tearDown(): void
    {
        $this->directory->remove();
    }

    #[Test]
    public function theProgramIsReplacedByTheFileOfTheNewestReleaseOfItsLine(): void
    {
        // Given
        $http = FakeGitHub::serving('0.0.2', hash('sha256', FakeGitHub::PROGRAM));

        // When
        $release = self::selfUpdate($http, FakeSignature::vouching())->update($this->runningPhar());

        // Then
        static::assertSame(['0.0.2', FakeGitHub::PROGRAM], [$release?->tag, file_get_contents($this->program)]);
    }

    #[Test]
    public function aProgramThatIsTheNewestOfItsLineIsLeftAsItIs(): void
    {
        // Given
        $http = FakeGitHub::serving('0.0.1', hash('sha256', FakeGitHub::PROGRAM));

        // When
        $release = self::selfUpdate($http, FakeSignature::vouching())->update($this->runningPhar());

        // Then
        static::assertSame([null, 'the old program', 1], [$release, file_get_contents($this->program), count($http->requests)]);
    }

    #[Test]
    public function aSignatureThatDoesNotVouchStopsTheUpdateBeforeTheProgramIsDownloaded(): void
    {
        // Given
        $http = FakeGitHub::serving('0.0.2', hash('sha256', FakeGitHub::PROGRAM));

        // When
        try {
            self::selfUpdate($http, FakeSignature::refusing())->update($this->runningPhar());
            static::fail('The update went on.');
        } catch (SelfUpdateException) {
        }

        // Then
        static::assertSame(
            ['the old program', false, ['.', '..', 'beffroi-tui']],
            [
                file_get_contents($this->program),
                in_array(FakeGitHub::download('0.0.2', 'beffroi-tui.phar'), array_column($http->requests, 'url'), true),
                scandir($this->directory->path),
            ],
        );
    }

    #[Test]
    public function theSignedSumsOfAnotherReleaseAreRefused(): void
    {
        // Given
        $http = FakeGitHub::serving('0.0.9', hash('sha256', FakeGitHub::PROGRAM), sumsOf: '0.0.2');

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('The signed SHA256SUMS served as the release 0.0.9 are those of another release: nothing is replaced.');

        // When
        self::selfUpdate($http, FakeSignature::vouching())->update($this->runningPhar());
    }

    #[Test]
    public function theSignedSumsOfAnotherReleaseStopTheUpdateBeforeTheProgramIsDownloaded(): void
    {
        // Given
        $http = FakeGitHub::serving('0.0.9', hash('sha256', FakeGitHub::PROGRAM), sumsOf: '0.0.2');

        // When
        try {
            self::selfUpdate($http, FakeSignature::vouching())->update($this->runningPhar());
            static::fail('The update went on.');
        } catch (SelfUpdateException) {
        }

        // Then
        static::assertSame(
            ['the old program', false, ['.', '..', 'beffroi-tui']],
            [
                file_get_contents($this->program),
                in_array(FakeGitHub::download('0.0.9', 'beffroi-tui.phar'), array_column($http->requests, 'url'), true),
                scandir($this->directory->path),
            ],
        );
    }

    #[Test]
    public function aFileThatIsNotTheOneTheSignedSumsNameIsRefused(): void
    {
        // Given
        $http = FakeGitHub::serving('0.0.2', hash('sha256', 'another program'));

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('The beffroi-tui.phar the release 0.0.2 served is not the one its signed SHA256SUMS names: nothing is replaced.');

        // When
        self::selfUpdate($http, FakeSignature::vouching())->update($this->runningPhar());
    }

    #[Test]
    public function aFileThatIsNotTheOneTheSignedSumsNameLeavesNothingBeside(): void
    {
        // Given
        $http = FakeGitHub::serving('0.0.2', hash('sha256', 'another program'));

        // When
        try {
            self::selfUpdate($http, FakeSignature::vouching())->update($this->runningPhar());
            static::fail('The update went on.');
        } catch (SelfUpdateException) {
        }

        // Then
        static::assertSame(['the old program', ['.', '..', 'beffroi-tui']], [file_get_contents($this->program), scandir($this->directory->path)]);
    }

    #[Test]
    public function aProgramThatRunsFromItsSourcesAsksGitHubNothing(): void
    {
        // Given
        $http = FakeGitHub::serving('0.0.2', hash('sha256', FakeGitHub::PROGRAM));

        // When
        try {
            self::selfUpdate($http, FakeSignature::vouching())->update(new RunningProgram('cli', '', 'Linux', 'x86_64', ReleaseVersion::fromTag('0.0.1')));
            static::fail('The update went on.');
        } catch (SelfUpdateException) {
        }

        // Then
        static::assertSame([], $http->requests);
    }

    private function runningPhar(): RunningProgram
    {
        return new RunningProgram('cli', $this->program, 'Linux', 'x86_64', ReleaseVersion::fromTag('0.0.1'));
    }

    private static function selfUpdate(RecordedRequests $http, SignatureVerifierInterface $signature): SelfUpdate
    {
        return new SelfUpdate(new GitHubReleases($http->client), new AssetDownload($http->client), $signature, new ProgramReplacement());
    }
}
