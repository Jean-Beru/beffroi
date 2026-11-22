<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Command;

use function file_get_contents;
use function file_put_contents;
use App\Command\GeoipRefreshCommand;
use App\Geo\GeoLite2Databases;
use App\Geo\GeoLite2Refresh;
use App\Tests\Symfony\Fixture\MaxMindDatabase;
use Closure;
use function memory_get_peak_usage;
use function memory_get_usage;
use function memory_reset_peak_usage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use function rtrim;
use function str_contains;
use function str_starts_with;
use function sprintf;
use function substr;
use function substr_count;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use function sys_get_temp_dir;
use function uniqid;

/**
 * Decision 0032
 */
final class GeoipRefreshCommandTest extends TestCase
{
    private const string LICENSE_KEY = 'a-licence-key-of-the-account';

    private const string SIGNATURE = '5d41402abc4b2a76';

    private const int LARGE_DATABASE_PADDING = 67_108_864;

    private const int MEMORY_HELD_AT_MOST = 16_777_216;

    private string $directory;

    private GeoLite2Databases $databases;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/beffroi-integration-tests/geoip-' . uniqid();
        new Filesystem()->mkdir($this->directory);
        $this->databases = new GeoLite2Databases($this->directory);
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->directory);
    }

    #[Test]
    public function bothEditionsAreDownloadedAndStoredUnderTheNameTheyDeclare(): void
    {
        // Given
        $asked = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url) use (&$asked): MockResponse {
            $asked[] = $url;

            return self::fromMaxMind($url, new MockResponse(MaxMindDatabase::archived(self::databaseOf($url))));
        }));

        // When
        $tester->execute([]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(
            [
                self::download(GeoLite2Databases::CITY),
                self::presigned(GeoLite2Databases::CITY),
                self::download(GeoLite2Databases::ASN),
                self::presigned(GeoLite2Databases::ASN),
            ],
            $asked,
        );
        static::assertSame(MaxMindDatabase::city(), file_get_contents($this->databases->path(GeoLite2Databases::CITY) ?? ''));
        static::assertSame(MaxMindDatabase::asn(), file_get_contents($this->databases->path(GeoLite2Databases::ASN) ?? ''));
    }

    #[Test]
    public function theLicenceKeyIsNotWrittenToTheConsole(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient(static fn (string $method, string $url): MockResponse => self::fromMaxMind(
            $url,
            new MockResponse(MaxMindDatabase::archived(self::databaseOf($url))),
        )));

        // When
        $tester->execute([]);

        // Then
        static::assertStringNotContainsString(self::LICENSE_KEY, $tester->getDisplay(true));
    }

    #[Test]
    public function itSaysWhatTheStoredDatabaseHolds(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient(static fn (string $method, string $url): MockResponse => self::fromMaxMind(
            $url,
            new MockResponse(MaxMindDatabase::archived(self::databaseOf($url))),
        )));

        // When
        $tester->execute([]);

        // Then
        static::assertStringContainsString(
            'The "GeoLite2-City" database of https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City '
            . 'is stored: built on 2026-01-01, a search tree of 1 nodes.',
            self::flattened($tester),
        );
    }

    #[Test]
    public function aSourceThatAnswersNothingChangedIsNotDownloadedAgain(): void
    {
        // Given
        $this->databases->write(
            GeoLite2Databases::CITY,
            MaxMindDatabase::inFile(MaxMindDatabase::city(), $this->directory),
            '"the-version-of-last-week"',
        );
        $sent = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url, array $options) use (&$sent): MockResponse {
            $sent[] = self::versionSentWith($options);

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

    #[Test]
    public function theVersionKeptIsTheOneTheStorageOfMaxMindAnswersWith(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient(static fn (string $method, string $url): MockResponse => self::fromMaxMind(
            $url,
            new MockResponse(MaxMindDatabase::archived(self::databaseOf($url)), [
                'response_headers' => [
                    'etag' => '"the-version-of-the-storage"',
                ],
            ]),
        )));

        // When
        $tester->execute([]);

        // Then
        static::assertSame('"the-version-of-the-storage"', $this->databases->version(GeoLite2Databases::CITY));
    }

    #[Test]
    public function aRunThatFindsTheVersionsItKeepsAsksTheStorageOfMaxMindWithThemAndDownloadsNothing(): void
    {
        // Given
        $this->databases->write(GeoLite2Databases::CITY, MaxMindDatabase::inFile(MaxMindDatabase::city(), $this->directory), '"the-city"');
        $this->databases->write(GeoLite2Databases::ASN, MaxMindDatabase::inFile(MaxMindDatabase::asn(), $this->directory), '"the-asn"');
        $sent = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url, array $options) use (&$sent): MockResponse {
            if (str_starts_with($url, GeoLite2Refresh::MAXMIND_DOWNLOAD)) {
                return self::redirectedTo(self::presigned(self::editionOf($url)));
            }
            $sent[] = self::versionSentWith($options);

            return new MockResponse('', [
                'http_code' => 304,
            ]);
        }));

        // When
        $tester->execute([]);

        // Then
        static::assertSame(
            [
                ['If-None-Match: "the-city"'],
                ['If-None-Match: "the-asn"'],
            ],
            $sent,
        );
        static::assertSame(2, substr_count(self::flattened($tester), 'is the one already stored, nothing was downloaded'));
    }

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

    #[Test]
    public function anArchiveTheSizeOfAnEditionOfMaxMindIsStoredWithoutBeingHeldInMemory(): void
    {
        // Given
        $archive = $this->directory . '/GeoLite2-City.tar.gz';
        MaxMindDatabase::archivedTo($archive, MaxMindDatabase::city(), self::LARGE_DATABASE_PADDING);
        $tester = $this->refresh(new MockHttpClient());

        // When
        memory_reset_peak_usage();
        $before = memory_get_usage();
        $tester->execute([
            '--url' => [$archive],
        ]);
        $held = memory_get_peak_usage() - $before;

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertLessThan(self::MEMORY_HELD_AT_MOST, $held);
    }

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
     * Decision 0006
     */
    #[Test]
    public function aSourceThatRedirectsIsRefusedWithTheUrlItNames(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient([self::redirectedTo('https://elsewhere.example/db.tar.gz')]));

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
     * Decision 0032
     */
    #[Test]
    public function aMirrorThatRedirectsToTheStorageOfMaxMindIsRefused(): void
    {
        // Given
        $asked = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url) use (&$asked): MockResponse {
            $asked[] = $url;

            return self::redirectedTo(self::presigned(GeoLite2Databases::CITY));
        }));

        // When
        $tester->execute([
            '--url' => ['https://mirror.example/GeoLite2-City.tar.gz'],
        ]);

        // Then
        static::assertSame(['https://mirror.example/GeoLite2-City.tar.gz'], $asked);
        static::assertStringContainsString('and no outbound request follows a redirect; name that URL instead', self::flattened($tester));
    }

    /**
     * Decision 0032
     */
    #[Test]
    #[DataProvider('provideWhatIsNotTheStorageOfMaxMind')]
    public function aRedirectOfMaxMindAnywhereButToItsStorageIsRefused(string $location): void
    {
        // Given
        $asked = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url) use (&$asked, $location): MockResponse {
            $asked[] = $url;

            return self::redirectedTo($location);
        }));

        // When
        $tester->execute([
            '--url' => [self::download(GeoLite2Databases::CITY)],
        ]);

        // Then
        static::assertSame([self::download(GeoLite2Databases::CITY)], $asked);
        static::assertStringContainsString(
            sprintf('is refused, nothing of it is kept: MaxMind redirects to %s rather than to %s', $location, GeoLite2Refresh::MAXMIND_STORAGE),
            self::flattened($tester),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideWhatIsNotTheStorageOfMaxMind(): iterable
    {
        $storage = rtrim(GeoLite2Refresh::MAXMIND_STORAGE, '/');
        yield 'its storage over plain http' => ['http' . substr($storage, 5) . '/GeoLite2-City.tar.gz'];
        yield 'its storage on another port' => [$storage . ':8443/GeoLite2-City.tar.gz'];
        yield 'another bucket of the same account' => [
            'https://mm-test-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com/GeoLite2-City.tar.gz',
        ];
        yield 'a host whose name starts with its own' => [$storage . '.elsewhere.example/GeoLite2-City.tar.gz'];
        yield 'another host behind credentials named after it' => [$storage . '@elsewhere.example/GeoLite2-City.tar.gz'];
        yield 'a path of MaxMind itself' => ['/app/geoip_download/GeoLite2-City.tar.gz'];
    }

    /**
     * @param Closure(string): MockResponse $answers
     */
    #[Test]
    #[DataProvider('provideRefusalsThatNameAUrl')]
    public function theReasonOfARefusalNamesEveryUrlWithoutItsQuery(string $source, Closure $answers): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient(static fn (string $method, string $url): MockResponse => $answers($url)));

        // When
        $tester->execute([
            '--url' => [$source],
        ]);

        // Then
        static::assertStringContainsString('is refused, nothing of it is kept', self::flattened($tester));
        static::assertStringNotContainsString(self::LICENSE_KEY, $tester->getDisplay(true));
        static::assertStringNotContainsString(self::SIGNATURE, $tester->getDisplay(true));
    }

    /**
     * @return iterable<string, array{string, Closure(string): MockResponse}>
     */
    public static function provideRefusalsThatNameAUrl(): iterable
    {
        yield 'MaxMind redirecting elsewhere' => [
            self::download(GeoLite2Databases::CITY),
            static fn (): MockResponse => self::redirectedTo('https://elsewhere.example/GeoLite2-City.tar.gz?X-Amz-Signature=' . self::SIGNATURE),
        ];
        yield 'a mirror redirecting to the storage of MaxMind' => [
            'https://mirror.example/GeoLite2-City.tar.gz',
            static fn (): MockResponse => self::redirectedTo(self::presigned(GeoLite2Databases::CITY)),
        ];
        yield 'MaxMind that stops answering' => [
            self::download(GeoLite2Databases::CITY),
            static fn (): MockResponse => new MockResponse(['']),
        ];
        yield 'the storage of MaxMind that stops answering' => [
            self::download(GeoLite2Databases::CITY),
            static fn (string $url): MockResponse => self::fromMaxMind($url, new MockResponse([''])),
        ];
    }

    #[Test]
    public function theStorageOfMaxMindRedirectingAgainIsRefused(): void
    {
        // Given
        $asked = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url) use (&$asked): MockResponse {
            $asked[] = $url;

            return self::fromMaxMind($url, self::redirectedTo('https://elsewhere.example/GeoLite2-City.tar.gz'));
        }));

        // When
        $tester->execute([
            '--url' => [self::download(GeoLite2Databases::CITY)],
        ]);

        // Then
        static::assertSame([self::download(GeoLite2Databases::CITY), self::presigned(GeoLite2Databases::CITY)], $asked);
        static::assertStringContainsString(
            'the storage of MaxMind redirects again, to https://elsewhere.example/GeoLite2-City.tar.gz, and no outbound request follows a second redirect',
            self::flattened($tester),
        );
    }

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

    private static function fromMaxMind(string $url, MockResponse $storage): MockResponse
    {
        return str_starts_with($url, GeoLite2Refresh::MAXMIND_DOWNLOAD) ? self::redirectedTo(self::presigned(self::editionOf($url))) : $storage;
    }

    private static function redirectedTo(string $location): MockResponse
    {
        return new MockResponse('', [
            'http_code' => 302,
            'response_headers' => [
                'location' => $location,
            ],
        ]);
    }

    private static function download(string $edition): string
    {
        return sprintf('%s?edition_id=%s&license_key=%s&suffix=tar.gz', GeoLite2Refresh::MAXMIND_DOWNLOAD, $edition, self::LICENSE_KEY);
    }

    private static function presigned(string $edition): string
    {
        return sprintf(
            '%sgeoip-databases/%s/%s_20261023.tar.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=3600&X-Amz-Signature=%s',
            GeoLite2Refresh::MAXMIND_STORAGE,
            $edition,
            $edition,
            self::SIGNATURE,
        );
    }

    private static function editionOf(string $url): string
    {
        return str_contains($url, GeoLite2Databases::ASN) ? GeoLite2Databases::ASN : GeoLite2Databases::CITY;
    }

    private static function databaseOf(string $url): string
    {
        return self::editionOf($url) === GeoLite2Databases::ASN ? MaxMindDatabase::asn() : MaxMindDatabase::city();
    }

    /**
     * @param array<mixed> $options
     */
    private static function versionSentWith(array $options): mixed
    {
        $headers = $options['normalized_headers'] ?? [];
        static::assertIsArray($headers);

        return $headers['if-none-match'] ?? null;
    }

    private static function flattened(CommandTester $tester): string
    {
        $display = preg_replace('/\s*\n\s*!?\s*/', ' ', $tester->getDisplay(true));
        static::assertIsString($display);

        return $display;
    }
}
