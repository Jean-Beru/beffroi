<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Command;

use function array_keys;
use function file_put_contents;
use Heidi\Bundle\Command\WebauthnMdsImportCommand;
use Heidi\Bundle\Command\WebauthnMdsRefreshCommand;
use Heidi\Core\Bridge\InMemory\InMemoryMetadataBlobStore;
use Heidi\Core\Bridge\Webauthn\MetadataBlobVerifier;
use Heidi\Core\Bridge\Webauthn\StoredMetadata;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\MetadataBlobs;
use Heidi\Core\Tests\Fixture\MetadataSigner;
use function json_decode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function preg_replace;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use function sys_get_temp_dir;
use function uniqid;
use Webauthn\MetadataService\CertificateChain\PhpCertificateChainValidator;

/**
 * Architecture §5.5: the FIDO metadata refreshed by hand from the service and verified under the pinned
 * root, a statement of a manufacturer or of the conformance tools imported as it is.
 */
final class WebauthnMdsCommandsTest extends TestCase
{
    private const string AAGUID = '2fc0579f-8113-47ea-b116-bb5a8db9202a';

    private MetadataSigner $service;

    private InMemoryMetadataBlobStore $store;

    private string $directory;

    protected function setUp(): void
    {
        $this->service = MetadataSigner::create();
        $this->store = new InMemoryMetadataBlobStore();
        $this->directory = sys_get_temp_dir() . '/heidi-bundle-tests/mds-' . uniqid();
        new Filesystem()->mkdir($this->directory);
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->directory);
    }

    #[Test]
    public function theBlobOfTheServiceIsDownloadedVerifiedAndStoredUnderTheNameOfItsSource(): void
    {
        // Given
        $blob = $this->service->sign(MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)], serialNumber: 7, nextUpdate: '2026-10-01'));
        $requests = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url, array $options) use ($blob, &$requests): MockResponse {
            $requests[] = [$method, $url, $options['max_redirects'] ?? null];

            return new MockResponse($blob);
        }));
        file_put_contents($this->directory . '/root.pem', $this->service->rootCertificate());

        // When
        $tester->execute([
            '--url' => ['https://mds.example/blob.jwt'],
            '--root' => $this->directory . '/root.pem',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame([['GET', 'https://mds.example/blob.jwt', 0]], $requests);
        $names = array_keys($this->store->readAll());
        static::assertCount(1, $names);
        static::assertMatchesRegularExpression('/^mds-mds\.example-[0-9a-f]{8}$/', $names[0]);
        static::assertSame(self::AAGUID, new StoredMetadata($this->store)->findOneByAAGUID(self::AAGUID)?->aaguid);
        static::assertStringContainsString('serial number 7, 1 entries, next update due on 2026-10-01', self::flattened($tester));
    }

    #[Test]
    public function theFidoMetadataServiceAndTheGlobalSignRootAreTheDefaults(): void
    {
        // Given
        $requests = [];
        $tester = $this->refresh(new MockHttpClient(static function (string $method, string $url) use (&$requests): MockResponse {
            $requests[] = $url;

            return new MockResponse('not a blob');
        }));

        // When
        $tester->execute([]);

        // Then
        static::assertSame([WebauthnMdsRefreshCommand::FIDO_METADATA_SERVICE], $requests);
        static::assertStringContainsString('The blob of https://mds.fidoalliance.org/ is refused', self::flattened($tester));
    }

    #[Test]
    public function aBlobSignedUnderAnotherRootIsRefusedAndNothingIsStored(): void
    {
        // Given
        $other = MetadataSigner::create('Another Service');
        $tester = $this->refresh(new MockHttpClient([new MockResponse($other->sign(MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)])))]));
        file_put_contents($this->directory . '/root.pem', $this->service->rootCertificate());

        // When
        $tester->execute([
            '--url' => ['https://mds.example/blob.jwt'],
            '--root' => $this->directory . '/root.pem',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame([], $this->store->readAll());
        static::assertStringContainsString(
            'refused, nothing of it is kept: The certificate chain of the blob does not lead to the pinned root',
            self::flattened($tester),
        );
    }

    /**
     * Decision 0006: no outbound request follows a redirect; the URL the service redirects to is named.
     */
    #[Test]
    public function aServiceThatRedirectsIsRefusedWithTheUrlItNames(): void
    {
        // Given
        $tester = $this->refresh(new MockHttpClient([new MockResponse('', [
            'http_code' => 301,
            'response_headers' => [
                'location' => 'https://mds.fidoalliance.org/',
            ],
        ])]));
        file_put_contents($this->directory . '/root.pem', $this->service->rootCertificate());

        // When
        $tester->execute([
            '--url' => ['https://mds3.fidoalliance.org/'],
            '--root' => $this->directory . '/root.pem',
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame([], $this->store->readAll());
        static::assertStringContainsString(
            'the service redirects to https://mds.fidoalliance.org/, and no outbound request follows a redirect; name that URL instead',
            self::flattened($tester),
        );
    }

    #[Test]
    public function theRootMayBeFetchedFromAnHttpsUrl(): void
    {
        // Given
        $blob = $this->service->sign(MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]));
        $root = $this->service->rootCertificate();
        $tester = $this->refresh(
            new MockHttpClient(
                static fn (string $method, string $url): MockResponse => new MockResponse($url === 'https://mds.example/root.crt' ? $root : $blob),
            ),
        );

        // When
        $tester->execute([
            '--url' => ['https://mds.example/blob.jwt'],
            '--root' => 'https://mds.example/root.crt',
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertCount(1, $this->store->readAll());
    }

    #[Test]
    public function aStatementIsImportedAsADocumentOfOneEntryWithoutStatusReport(): void
    {
        // Given
        $statement = MetadataBlobs::entry(self::AAGUID, description: 'Virtual authenticator of the tools')['metadataStatement'];
        static::assertIsArray($statement);
        file_put_contents($this->directory . '/statement.json', json_encode($statement, JSON_THROW_ON_ERROR));
        $tester = $this->import();

        // When
        $tester->execute([
            'files' => [$this->directory . '/statement.json'],
        ]);

        // Then
        static::assertSame(Command::SUCCESS, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame(['statement-' . self::AAGUID], array_keys($this->store->readAll()));
        $document = json_decode($this->store->readAll()['statement-' . self::AAGUID], true, 16, JSON_THROW_ON_ERROR);
        static::assertSame(
            [
                'legalHeader' => 'For the tests.',
                'no' => 0,
                'nextUpdate' => '2026-09-15',
                'entries' => [[
                    'aaguid' => self::AAGUID,
                    'metadataStatement' => $statement,
                    'statusReports' => [],
                    'timeOfLastStatusChange' => '2026-09-15',
                ]],
            ],
            $document,
        );
        $metadata = new StoredMetadata($this->store);
        static::assertSame('Virtual authenticator of the tools', $metadata->findOneByAAGUID(self::AAGUID)?->description);
        static::assertSame([], $metadata->findStatusReportsByAAGUID(self::AAGUID));
    }

    #[Test]
    public function aFileThatIsNotAStatementIsRefusedAndNothingIsStored(): void
    {
        // Given
        file_put_contents($this->directory . '/statement.json', '{"description": "no aaguid, no schema"}');
        $tester = $this->import();

        // When
        $tester->execute([
            'files' => [$this->directory . '/statement.json'],
        ]);

        // Then
        static::assertSame(Command::FAILURE, $tester->getStatusCode(), $tester->getDisplay());
        static::assertSame([], $this->store->readAll());
        static::assertStringContainsString('is not a metadata statement, nothing of it is kept', self::flattened($tester));
    }

    private function refresh(MockHttpClient $http): CommandTester
    {
        $verifier = new MetadataBlobVerifier(PhpCertificateChainValidator::create(new MockHttpClient(), new MockClock(Fixtures::now())));

        return new CommandTester(new Command('heidi:webauthn:mds-refresh')->setCode(new WebauthnMdsRefreshCommand($http, $verifier, $this->store)));
    }

    private function import(): CommandTester
    {
        return new CommandTester(new Command('heidi:webauthn:mds-import')->setCode(new WebauthnMdsImportCommand($this->store, new MockClock(Fixtures::now()))));
    }

    private static function flattened(CommandTester $tester): string
    {
        $display = preg_replace('/\s*\n\s*!?\s*/', ' ', $tester->getDisplay(true));
        static::assertIsString($display);

        return $display;
    }
}
