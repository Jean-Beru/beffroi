<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Fixture;

use Beffroi\Tui\Screen\ThisProgram;
use Beffroi\Tui\Update\GitHubReleases;
use Beffroi\Tui\Update\ReleaseVersion;
use LogicException;
use function sprintf;

/**
 * This program as a screen under test runs it: from its sources, which look for no release, or as a release whose
 * releases GitHub answers as the requests given say.
 */
final readonly class Programs
{
    public static function fromItsSources(): ThisProgram
    {
        return new ThisProgram(null, null, new GitHubReleases(RecordedRequests::answering([])->client));
    }

    public static function release(string $tag, RecordedRequests $github): ThisProgram
    {
        return new ThisProgram(
            ReleaseVersion::fromTag($tag) ?? throw new LogicException(sprintf('%s is not a release tag.', $tag)),
            null,
            new GitHubReleases($github->client),
        );
    }
}
