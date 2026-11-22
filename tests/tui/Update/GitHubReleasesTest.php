<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Update;

use Beffroi\Tui\Tests\Fixture\RecordedRequests;
use Beffroi\Tui\Update\GitHubReleases;
use Beffroi\Tui\Update\ReleaseAsset;
use Beffroi\Tui\Update\ReleaseVersion;
use Beffroi\Tui\Update\SelfUpdateException;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The releases read from the GitHub REST API, "List releases", without a credential.
 */
final class GitHubReleasesTest extends TestCase
{
    #[Test]
    public function theNewestReleaseOfTheLineAboveTheRunningOneIsFound(): void
    {
        // Given
        $http = self::answering([self::release('0.0.2'), self::release('0.1.0'), self::release('0.0.4'), self::release('0.0.3')]);

        // When
        $release = new GitHubReleases($http->client)->newestInTheLineOf(self::version('0.0.1'));

        // Then
        static::assertSame('0.0.4', $release?->version->tag);
    }

    #[Test]
    public function theReleasesAreListedWithoutACredential(): void
    {
        // Given
        $http = self::answering([]);

        // When
        new GitHubReleases($http->client)->newestInTheLineOf(self::version('0.0.1'));

        // Then
        static::assertSame(
            ['GET', 'https://api.github.com/repos/beffroi-auth/beffroi/releases?per_page=100', null],
            [$http->last()['method'], $http->last()['url'], $http->last()['headers']['authorization'] ?? null],
        );
    }

    /**
     * @param array<string, mixed> $release
     */
    #[Test]
    #[DataProvider('provideReleasesThatDoNotCount')]
    public function aReleaseThatIsNotAPublishedReleaseOfTheLineAboveIsNotTaken(array $release): void
    {
        // Given
        $http = self::answering([$release]);

        // When
        $found = new GitHubReleases($http->client)->newestInTheLineOf(self::version('0.0.1'));

        // Then
        static::assertNull($found);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideReleasesThatDoNotCount(): iterable
    {
        yield 'the running one' => [self::release('0.0.1')];
        yield 'one below' => [self::release('0.0.0')];
        yield 'another line' => [self::release('0.1.0')];
        yield 'a draft' => [self::release('0.0.2', ['draft' => true])];
        yield 'a prerelease' => [self::release('0.0.2', ['prerelease' => true])];
        yield 'one that does not say it is no draft' => [self::release('0.0.2', ['draft' => null])];
        yield 'a tag that is no release tag' => [self::release('0.0.2', ['tag_name' => 'v0.0.2'])];
    }

    #[Test]
    public function theFilesOfTheReleaseFoundAreThoseItUploadedWhole(): void
    {
        // Given
        $http = self::answering([self::release('0.0.2', [
            'assets' => [
                self::asset('0.0.2', 'beffroi-tui.phar', 2_904_531),
                self::asset('0.0.2', 'SHA256SUMS', 358),
                [
                    'state' => 'open',
                    'name' => 'beffroi-tui-linux-x86_64',
                    'size' => 1,
                    'browser_download_url' => GitHubReleases::DOWNLOADS . '0.0.2/beffroi-tui-linux-x86_64',
                ],
            ],
        ])]);

        // When
        $release = new GitHubReleases($http->client)->newestInTheLineOf(self::version('0.0.1'));

        // Then
        static::assertEquals(
            [
                'beffroi-tui.phar' => new ReleaseAsset(
                    'beffroi-tui.phar',
                    'https://github.com/beffroi-auth/beffroi/releases/download/0.0.2/beffroi-tui.phar',
                    2_904_531,
                ),
                'SHA256SUMS' => new ReleaseAsset('SHA256SUMS', 'https://github.com/beffroi-auth/beffroi/releases/download/0.0.2/SHA256SUMS', 358),
            ],
            $release?->assets,
        );
    }

    #[Test]
    #[DataProvider('provideDownloadAddressesElsewhere')]
    public function aFileOfTheReleaseFoundServedElsewhereIsRefused(string $url): void
    {
        // Given
        $http = self::answering([self::release('0.0.2', [
            'assets' => [
                ['state' => 'uploaded', 'name' => 'beffroi-tui.phar', 'size' => 10, 'browser_download_url' => $url],
            ],
        ])]);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs(sprintf(
            'The release 0.0.2 names its file beffroi-tui.phar at %s, and not at https://github.com/beffroi-auth/beffroi/releases/download/0.0.2/beffroi-tui.phar.',
            $url,
        ));

        // When
        new GitHubReleases($http->client)->newestInTheLineOf(self::version('0.0.1'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideDownloadAddressesElsewhere(): iterable
    {
        yield 'another host' => ['https://example.com/beffroi-tui.phar'];
        yield 'another repository' => ['https://github.com/someone/beffroi/releases/download/0.0.2/beffroi-tui.phar'];
        yield 'another release' => ['https://github.com/beffroi-auth/beffroi/releases/download/0.0.1/beffroi-tui.phar'];
        yield 'plain HTTP' => ['http://github.com/beffroi-auth/beffroi/releases/download/0.0.2/beffroi-tui.phar'];
    }

    #[Test]
    public function aListGitHubDoesNotShowIsRefused(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"message": "Not Found"}', ['http_code' => 404])]);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('GitHub shows no release of beffroi-auth/beffroi to a reader without credentials (404).');

        // When
        new GitHubReleases($http->client)->newestInTheLineOf(self::version('0.0.1'));
    }

    #[Test]
    public function aListThatIsNotAListIsRefused(): void
    {
        // Given
        $http = RecordedRequests::answering([new MockResponse('{"message": "rate limited"}')]);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('GitHub answered a list of the releases of beffroi-auth/beffroi that is not readable: The list of the releases must be a JSON list.');

        // When
        new GitHubReleases($http->client)->newestInTheLineOf(self::version('0.0.1'));
    }

    /**
     * No boolean from a third party is cast (decision 0006).
     */
    #[Test]
    public function aDraftFlagThatIsNoBooleanIsRefused(): void
    {
        // Given
        $http = self::answering([self::release('0.0.2', ['draft' => 'false'])]);

        // Then
        $this->expectException(SelfUpdateException::class);
        $this->expectExceptionMessageIs('GitHub answered a list of the releases of beffroi-auth/beffroi that is not readable: The member "draft" must be a boolean or absent.');

        // When
        new GitHubReleases($http->client)->newestInTheLineOf(self::version('0.0.1'));
    }

    private static function version(string $tag): ReleaseVersion
    {
        return ReleaseVersion::fromTag($tag) ?? static::fail(sprintf('%s is a release tag.', $tag));
    }

    /**
     * @param list<array<string, mixed>> $releases
     */
    private static function answering(array $releases): RecordedRequests
    {
        return RecordedRequests::answering([new MockResponse(json_encode($releases, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES))]);
    }

    /**
     * A release as the API lists it, the members given replacing those of the same name.
     *
     * @param array<string, mixed> $replacing
     *
     * @return array<string, mixed>
     */
    private static function release(string $tag, array $replacing = []): array
    {
        return [
            'tag_name' => $tag,
            'draft' => false,
            'prerelease' => false,
            'assets' => [self::asset($tag, 'beffroi-tui.phar', 2_904_531)],
            ...$replacing,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function asset(string $tag, string $name, int $size): array
    {
        return [
            'name' => $name,
            'state' => 'uploaded',
            'size' => $size,
            'browser_download_url' => GitHubReleases::DOWNLOADS . $tag . '/' . $name,
        ];
    }
}
