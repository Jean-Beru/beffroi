<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Command;

use function file_get_contents;
use function file_put_contents;
use Beffroi\Bundle\Command\GeoipRefreshCommand;
use Beffroi\Bundle\Geo\GeoLite2Databases;
use Beffroi\Bundle\Geo\GeoLite2Refresh;
use Beffroi\Bundle\Tests\Fixture\MaxMindDatabase;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function str_contains;
use function sprintf;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use function sys_get_temp_dir;
use function uniqid;

/**
 * Issue #473: the databases of addresses downloaded, refused unless they are ones this provider reads,
 * and stored where the lane reads them. The weekly step of the schedule runs the same object.
 */
final class GeoipRefreshCommandTest extends TestCase
{
    private const string LICENSE_KEY = 'a-licence-key-of-the-account';

    private string $directory;

    private GeoLite2Databases $databases;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/beffroi-bundle-tests/geoip-' . uniqid();
        new Filesystem()->mkdir($this->directory);
        $this->databases = new GeoLite2Databases($this->directory);
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->directory);
    }

    /**
     * Both editions asked for at MaxMind under the licence key of the deployment, and stored under the
     * name each one declares itself by rather than the name of the source.
     */
    #[Test]
    public function bothEditionsAreDownloadedAndStoredUnderTheNameTheyDeclare(): void
    {
        // Given
        $asked = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url) use (&$asked): MockResponse {
            $asked[] = $url;

            return new MockResponse(MaxMindDatabase::archived(
                str_contains($url, GeoLite2Databases::ASN) ? MaxMindDatabase::asn() : MaxMindDatabase::city(),
            ));
        }));

        // When
        $tester->execute([]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(
            [
                sprintf('%s?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz', GeoLite2Refresh::MAXMIND_DOWNLOAD, self::LICENSE_KEY),
                sprintf('%s?edition_id=GeoLite2-ASN&license_key=%s&suffix=tar.gz', GeoLite2Refresh::MAXMIND_DOWNLOAD, self::LICENSE_KEY),
            ],
            $asked,
        );
        static::assertSame(MaxMindDatabase::city(), file_get_contents($this->databases->path(GeoLite2Databases::CITY) ?? ''));
        static::assertSame(MaxMindDatabase::asn(), file_get_contents($this->databases->path(GeoLite2Databases::ASN) ?? ''));
    }

    /**
     * What a console writes is read again in a log and over a shoulder: the licence key of the deployment
     * is not part of what it writes.
     */
    #[Test]
    public function theLicenceKeyIsNotWrittenToTheConsole(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient(
            static fn (): MockResponse => new MockResponse(MaxMindDatabase::archived(MaxMindDatabase::city())),
        ));

        // When
        $tester->execute([]);

        // Then
        static::assertStringNotContainsString(self::LICENSE_KEY, $tester->getDisplay(true));
    }

    /**
     * The database says when it was built and how many networks it holds, which is what "it did
     * something" means for a refresh.
     */
    #[Test]
    public function itSaysWhatTheStoredDatabaseHolds(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient(
            static fn (): MockResponse => new MockResponse(MaxMindDatabase::archived(MaxMindDatabase::city())),
        ));

        // When
        $tester->execute([]);

        // Then
        static::assertStringContainsString(
            'The "GeoLite2-City" database of https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City '
            . 'is stored: built on 2026-01-01, a search tree of 1 nodes.',
            self::flattened($tester),
        );
    }

    /**
     * The ETag of what is stored goes out with the next request, and a source that answers that nothing
     * changed is a week that costs no download.
     */
    #[Test]
    public function aSourceThatAnswersNothingChangedIsNotDownloadedAgain(): void
    {
        // Given
        $this->databases->write(GeoLite2Databases::CITY, MaxMindDatabase::city(), '"the-version-of-last-week"');
        $sent = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url, array $options) use (&$sent): MockResponse {
            $headers = $options['normalized_headers'] ?? [];
            static::assertIsArray($headers);
            $sent[] = $headers['if-none-match'] ?? null;

            return new MockResponse('', [
                'http_code' => 304,
            ]);
        }));

        // When
        $tester->execute([
            '--url' => [GeoLite2Refresh::MAXMIND_DOWNLOAD . '?edition_id=GeoLite2-City'],
        ]);

        // Then
        static::assertSame([['If-None-Match: "the-version-of-last-week"']], $sent);
        static::assertStringContainsString('is the one already stored, nothing was downloaded', self::flattened($tester));
    }

    /**
     * A deployment may hold a database a mirror serves or one it unpacked by hand, which is what --url
     * names; the edition is read from the file and not from the name it was given.
     */
    #[Test]
    public function aDatabaseNamedAsAFileIsStoredUnderTheEditionItDeclares(): void
    {
        // Given
        file_put_contents($this->directory . '/downloaded-by-hand', MaxMindDatabase::asn());
        $tester = $this->refresh(new MockHttpClient());

        // When
        $tester->execute([
            '--url' => [$this->directory . '/downloaded-by-hand'],
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNotNull($this->databases->path(GeoLite2Databases::ASN));
    }

    /**
     * An edition the enrichment does not read is refused rather than stored: a file nothing reads is a
     * file nobody notices is the wrong one.
     */
    #[Test]
    public function anEditionTheEnrichmentDoesNotReadIsRefusedAndNothingIsStored(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient(
            static fn (): MockResponse => new MockResponse(MaxMindDatabase::archived(MaxMindDatabase::of('GeoLite2-Country', [
                'country' => [
                    'iso_code' => 'GB',
                ],
            ]))),
        ));

        // When
        $tester->execute([
            '--url' => ['https://mirror.example/GeoLite2-Country.tar.gz'],
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertNull($this->databases->path(GeoLite2Databases::CITY));
        static::assertStringContainsString(
            'is refused, nothing of it is kept: it is a "GeoLite2-Country" database, which the enrichment of a provenance does not read',
            self::flattened($tester),
        );
    }

    /**
     * Decision 0006: no outbound request follows a redirect; the URL the source names is said instead.
     */
    #[Test]
    public function aSourceThatRedirectsIsRefusedWithTheUrlItNames(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient([new MockResponse('', [
            'http_code' => 302,
            'response_headers' => [
                'location' => 'https://elsewhere.example/db.tar.gz',
            ],
        ])]));

        // When
        $tester->execute([
            '--url' => ['https://mirror.example/GeoLite2-City.tar.gz'],
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString(
            'the source redirects to https://elsewhere.example/db.tar.gz, and no outbound request follows a redirect; name that URL instead',
            self::flattened($tester),
        );
    }

    /**
     * A deployment that named no licence key has nothing to download, and is told what to write rather
     * than left with a run that did nothing.
     */
    #[Test]
    public function aDeploymentThatNamesNoLicenceKeyIsToldWhatToWrite(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient(), licenseKey: '');

        // When
        $tester->execute([]);

        // Then
        static::assertSame(Command::INVALID, $tester->getStatusCode(), $tester->getDisplay());
        static::assertStringContainsString('GEOIP_LICENSE_KEY', self::flattened($tester));
    }

    private function refresh(MockHttpClient $http, string $licenseKey = self::LICENSE_KEY): CommandTester
    {
        return new CommandTester(new Command('beffroi:geoip:refresh')->setCode(
            new GeoipRefreshCommand(new GeoLite2Refresh($http, $this->databases, $licenseKey)),
        ));
    }

    private static function flattened(CommandTester $tester): string
    {
        $display = preg_replace('/\s*\n\s*!?\s*/', ' ', $tester->getDisplay(true));
        static::assertIsString($display);

        return $display;
    }
}
