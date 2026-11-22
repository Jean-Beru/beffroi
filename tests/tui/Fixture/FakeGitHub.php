<?php

declare(strict_types=1);

namespace Beffroi\Tui\Tests\Fixture;

use Beffroi\Tui\Update\GitHubReleases;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use function sprintf;
use function strlen;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * GitHub serving one release of the repository: its listing in the REST API, its `SHA256SUMS` giving the digest
 * given for the PHAR, a signature, and the PHAR itself.
 */
final readonly class FakeGitHub
{
    public const string PROGRAM = 'the new program';

    public static function serving(string $tag, string $digest): RecordedRequests
    {
        $files = [
            'SHA256SUMS' => sprintf("%s  beffroi-tui.phar\n", $digest),
            'SHA256SUMS.asc' => "-----BEGIN PGP SIGNATURE-----\n-----END PGP SIGNATURE-----\n",
            'beffroi-tui.phar' => self::PROGRAM,
        ];
        $assets = [];
        foreach ($files as $name => $content) {
            $assets[] = ['name' => $name, 'state' => 'uploaded', 'size' => strlen($content), 'browser_download_url' => self::download($tag, $name)];
        }
        $releases = json_encode([[
            'tag_name' => $tag,
            'draft' => false,
            'prerelease' => false,
            'assets' => $assets,
        ]], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        return RecordedRequests::routed(static function (string $method, string $url) use ($releases, $files, $tag): MockResponse {
            if ($url === GitHubReleases::LIST) {
                return new MockResponse($releases);
            }
            foreach ($files as $name => $content) {
                if ($url === self::download($tag, $name)) {
                    return new MockResponse($content);
                }
            }

            return new MockResponse('', ['http_code' => 404]);
        });
    }

    public static function download(string $tag, string $name): string
    {
        return GitHubReleases::DOWNLOADS . $tag . '/' . $name;
    }
}
