<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Screen;

use Beffroi\Tui\Screen\ThisProgram;
use Beffroi\Tui\Tests\Fixture\FakeGitHub;
use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use Beffroi\Tui\Update\GitHubReleases;
use Beffroi\Tui\Update\ReleaseVersion;
use function count;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The build the screen names, and the newer release of its line it looks for once per run.
 */
final class ThisProgramTest extends TestCase
{
    /**
     * @param array{string, array<string, string>} $said
     */
    #[Test]
    #[DataProvider('provideBuilds')]
    public function theScreenNamesTheBuildThatRuns(?string $release, ?string $build, array $said): void
    {
        // Given
        $program = new ThisProgram(self::version($release), $build, new GitHubReleases(RecordedRequests::answering([])->client));

        // When / Then
        static::assertSame($said, $program->version());
    }

    /**
     * @return iterable<string, array{?string, ?string, array{string, array<string, string>}}>
     */
    public static function provideBuilds(): iterable
    {
        yield 'a release' => ['0.1.0', null, ['program.release', ['version' => '0.1.0']]];
        yield 'a build of a branch' => [null, '0.1.x-84491c5', ['program.build', ['build' => '0.1.x-84491c5']]];
        yield 'the sources' => [null, null, ['program.sources', []]];
    }

    #[Test]
    #[DataProvider('provideNames')]
    public function theVersionPrintedIsTheReleaseOrTheBuild(?string $release, ?string $build, ?string $name): void
    {
        // Given
        $program = new ThisProgram(self::version($release), $build, new GitHubReleases(RecordedRequests::answering([])->client));

        // When / Then
        static::assertSame($name, $program->name());
    }

    /**
     * @return iterable<string, array{?string, ?string, ?string}>
     */
    public static function provideNames(): iterable
    {
        yield 'a release' => ['0.1.0', null, '0.1.0'];
        yield 'a build of a branch' => [null, '0.1.x-84491c5', '0.1.x-84491c5'];
        yield 'the sources' => [null, null, null];
    }

    #[Test]
    public function aReleaseSaysItIsLookingUntilTheReleasesAnswer(): void
    {
        // Given
        $program = new ThisProgram(self::version('0.1.0'), null, new GitHubReleases(RecordedRequests::answering([])->client));

        // When / Then
        static::assertSame(['program.looking', []], $program->update());
    }

    #[Test]
    public function aNewerReleaseOfTheLineIsNamed(): void
    {
        // Given
        $program = new ThisProgram(self::version('0.1.0'), null, new GitHubReleases(FakeGitHub::serving('0.1.1', str_repeat('0', 64))->client));

        // When
        $program->lookForANewerRelease();

        // Then
        static::assertSame(['program.newer', ['version' => '0.1.1']], $program->update());
    }

    #[Test]
    public function aReleaseWithNoneNewerInItsLineSaysItsLine(): void
    {
        // Given
        $program = new ThisProgram(self::version('0.1.0'), null, new GitHubReleases(FakeGitHub::serving('0.2.0', str_repeat('0', 64))->client));

        // When
        $program->lookForANewerRelease();

        // Then
        static::assertSame(['program.newest', ['line' => '0.1.x']], $program->update());
    }

    #[Test]
    public function releasesThatCannotBeReadAreSaidWithTheReason(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"message":"Not Found"}', ['http_code' => 404])]);
        $program = new ThisProgram(self::version('0.1.0'), null, new GitHubReleases($http->client));

        // When
        $program->lookForANewerRelease();

        // Then
        static::assertSame(
            ['program.unchecked', ['reason' => 'GitHub shows no release of beffroi-auth/beffroi to a reader without credentials (404).']],
            $program->update(),
        );
    }

    #[Test]
    public function theReleasesAreReadOncePerRun(): void
    {
        // Given
        $http = FakeGitHub::serving('0.1.1', str_repeat('0', 64));
        $program = new ThisProgram(self::version('0.1.0'), null, new GitHubReleases($http->client));
        $program->lookForANewerRelease();

        // When
        $program->lookForANewerRelease();

        // Then
        static::assertCount(1, $http->requests);
    }

    #[Test]
    #[DataProvider('provideWhatIsNoRelease')]
    public function aBuildThatIsNoReleaseAsksNothing(?string $build): void
    {
        // Given
        $http = FakeGitHub::serving('0.1.1', str_repeat('0', 64));
        $program = new ThisProgram(null, $build, new GitHubReleases($http->client));

        // When
        $program->lookForANewerRelease();

        // Then
        static::assertSame([0, null], [count($http->requests), $program->update()]);
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideWhatIsNoRelease(): iterable
    {
        yield 'a build of a branch' => ['0.1.x-84491c5'];
        yield 'the sources' => [null];
    }

    private static function version(?string $tag): ?ReleaseVersion
    {
        return $tag === null ? null : ReleaseVersion::fromTag($tag) ?? static::fail($tag . ' is a release tag.');
    }
}
