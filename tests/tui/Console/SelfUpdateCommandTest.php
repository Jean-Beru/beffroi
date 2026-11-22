<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Console;

use Beffroi\Tui\Console\SelfUpdateCommand;
use Beffroi\Tui\Tests\Fixture\FakeGitHub;
use Beffroi\Tui\Tests\Fixture\FakeSignature;
use Beffroi\Tui\Update\AssetDownload;
use Beffroi\Tui\Update\GitHubReleases;
use Beffroi\Tui\Update\ProgramReplacement;
use Beffroi\Tui\Update\ReleaseVersion;
use Beffroi\Tui\Update\RunningProgram;
use Beffroi\Tui\Update\SelfUpdate;
use Beffroi\Tui\Update\SignatureVerifierInterface;
use Beffroi\Tui\Update\TemporaryDirectory;
use function file_put_contents;
use function hash;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\Test;
use function preg_replace;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;
use function trim;

/**
 * What the command says of an update, and how it ends.
 */
final class SelfUpdateCommandTest extends TestCase
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
    public function anUpdateNamesTheReleaseTheProgramIsNow(): void
    {
        // When
        [$status, $said] = $this->runTheCommand(FakeSignature::vouching(), '0.0.2');

        // Then
        static::assertSame([0, '[OK] This program is now the release 0.0.2, which its signature vouches for.'], [$status, $said]);
    }

    #[Test]
    public function aProgramThatIsTheNewestOfItsLineIsSaidToBe(): void
    {
        // When
        [$status, $said] = $this->runTheCommand(FakeSignature::vouching(), '0.0.1');

        // Then
        static::assertSame([0, '[OK] This program, 0.0.1, is the newest release of its line.'], [$status, $said]);
    }

    #[Test]
    public function aRefusalIsSaidAndEndsInAFailure(): void
    {
        // When
        [$status, $said] = $this->runTheCommand(FakeSignature::refusing(), '0.0.2');

        // Then
        static::assertSame([1, '[ERROR] ' . FakeSignature::REFUSAL], [$status, $said]);
    }

    /**
     * @return array{int, string} the status the command ends with, and what it wrote on one line
     */
    private function runTheCommand(SignatureVerifierInterface $signature, string $newest): array
    {
        $http = FakeGitHub::serving($newest, hash('sha256', FakeGitHub::PROGRAM));
        $application = new Application();
        $application->addCommand(new SelfUpdateCommand(
            new SelfUpdate(new GitHubReleases($http->client), new AssetDownload($http->client), $signature, new ProgramReplacement()),
            new RunningProgram('cli', $this->program, 'Linux', 'x86_64', ReleaseVersion::fromTag('0.0.1')),
        ));
        $tester = new CommandTester($application->find(SelfUpdateCommand::NAME));
        $status = $tester->execute([]);

        return [$status, trim((string) preg_replace('/\s+/', ' ', $tester->getDisplay()))];
    }
}
