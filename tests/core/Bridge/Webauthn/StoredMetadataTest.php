<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\InMemory\InMemoryMetadataBlobStore;
use Beffroi\Core\Bridge\Webauthn\StoredMetadata;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strtoupper;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;
use Webauthn\MetadataService\Statement\StatusReport;

final class StoredMetadataTest extends TestCase
{
    private const string AAGUID = '2fc0579f-8113-47ea-b116-bb5a8db9202a';

    private InMemoryMetadataBlobStore $store;

    private StoredMetadata $metadata;

    protected function setUp(): void
    {
        $this->store = new InMemoryMetadataBlobStore();
        $this->metadata = new StoredMetadata($this->store);
    }

    #[Test]
    #[DataProvider('provideAaguidSpellings')]
    public function theStatementAndTheReportsOfAnAuthenticatorAreFoundByItsAaguid(string $aaguid): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(
            self::AAGUID,
            [AuthenticatorStatus::FIDO_CERTIFIED, AuthenticatorStatus::USER_VERIFICATION_BYPASS],
            'Compromised key',
        )]));

        // When
        $statement = $this->metadata->findOneByAAGUID($aaguid);
        $reports = $this->metadata->findStatusReportsByAAGUID($aaguid);

        // Then
        static::assertSame('Compromised key', $statement?->description);
        static::assertSame(
            [AuthenticatorStatus::FIDO_CERTIFIED, AuthenticatorStatus::USER_VERIFICATION_BYPASS],
            array_map(static fn (StatusReport $report): string => $report->status, $reports),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideAaguidSpellings(): iterable
    {
        yield 'as the service writes it' => [self::AAGUID];
        yield 'in upper case' => [strtoupper(self::AAGUID)];
    }

    /**
     * FIDO Metadata Statement v3.1 §4
     */
    #[Test]
    public function aStatementThatLeavesOutTheUserVerificationDetailsIsFoundByItsAaguid(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([
            MetadataBlobs::entry(self::AAGUID, description: 'Passkey provider', omitting: ['userVerificationDetails']),
        ]));

        // When
        $statement = $this->metadata->findOneByAAGUID(self::AAGUID);

        // Then
        static::assertSame('Passkey provider', $statement?->description);
    }

    #[Test]
    public function aDocumentSpellingAnAaguidInUpperCaseIsFoundByTheLowerCaseSpelling(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(strtoupper(self::AAGUID))]));

        // When
        $statement = $this->metadata->findOneByAAGUID(self::AAGUID);

        // Then
        static::assertSame(strtoupper(self::AAGUID), $statement?->aaguid);
    }

    #[Test]
    public function anAuthenticatorTheStoreDoesNotDescribeIsUnknown(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]));

        // When
        $statement = $this->metadata->findOneByAAGUID('00000000-0000-0000-0000-000000000001');
        $reports = $this->metadata->findStatusReportsByAAGUID('00000000-0000-0000-0000-000000000001');

        // Then
        static::assertNull($statement);
        static::assertSame([], $reports);
    }

    #[Test]
    public function anEmptyStoreKnowsNoAuthenticator(): void
    {
        // When
        $statement = $this->metadata->findOneByAAGUID(self::AAGUID);

        // Then
        static::assertNull($statement);
    }

    #[Test]
    public function theDocumentReadLastDescribesAnAuthenticatorTwoDocumentsDescribe(): void
    {
        // Given
        $this->store->write('b-later', MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID, description: 'Later')]));
        $this->store->write('a-earlier', MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID, description: 'Earlier')]));

        // When
        $statement = $this->metadata->findOneByAAGUID(self::AAGUID);

        // Then
        static::assertSame('Later', $statement?->description);
    }

    #[Test]
    public function anEntryWithoutStatementIsIgnored(): void
    {
        // Given
        $entry = MetadataBlobs::entry(self::AAGUID);
        unset($entry['metadataStatement']);
        $this->store->write('mds', MetadataBlobs::payload([$entry]));

        // When
        $statement = $this->metadata->findOneByAAGUID(self::AAGUID);

        // Then
        static::assertNull($statement);
    }

    /**
     * FIDO Metadata Service v3.1.1 §3.1.1
     */
    #[Test]
    public function anEntryWithoutAaguidIsIgnored(): void
    {
        // Given
        $entry = MetadataBlobs::entry(self::AAGUID);
        unset($entry['aaguid']);
        $entry['attestationCertificateKeyIdentifiers'] = ['7c0903708b87115b0b422def3138c3c864e44573'];
        $this->store->write('mds', MetadataBlobs::payload([$entry]));

        // When
        $statement = $this->metadata->findOneByAAGUID(self::AAGUID);

        // Then
        static::assertNull($statement);
    }

    #[Test]
    public function theStoreIsReadOnce(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]));
        $this->metadata->findOneByAAGUID(self::AAGUID);
        $this->store->write('mds', MetadataBlobs::payload([]));

        // When
        $statement = $this->metadata->findOneByAAGUID(self::AAGUID);

        // Then
        static::assertSame(self::AAGUID, $statement?->aaguid);
    }

    #[Test]
    public function aDocumentThatIsNotABlobPayloadIsADefectOfTheStore(): void
    {
        // Given
        $this->store->write('broken', '{"entries": "none"}');

        // Then
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageIsOrContains('The metadata document "broken" is not a Metadata BLOB payload');

        // When
        $this->metadata->findOneByAAGUID(self::AAGUID);
    }
}
