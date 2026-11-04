<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Bridge\Webauthn;

use Beffroi\Core\Bridge\InMemory\InMemoryMetadataBlobStore;
use Beffroi\Core\Bridge\Webauthn\MetadataAuthenticatorModels;
use Beffroi\Core\Bridge\Webauthn\StoredMetadata;
use Beffroi\Core\Domain\Credential\FidoCertification;
use Beffroi\Core\Tests\Fixture\AuthenticatorImages;
use Beffroi\Core\Tests\Fixture\MetadataBlobs;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\MetadataService\Statement\AuthenticatorStatus;

/**
 * FIDO Metadata Statement v3.1.1 §4, FIDO Metadata Service v3.1.1 §3.1.4.1
 */
final class MetadataAuthenticatorModelsTest extends TestCase
{
    private const string AAGUID = 'ee882879-721c-4913-9775-3dfcce97072a';

    private InMemoryMetadataBlobStore $store;

    private MetadataAuthenticatorModels $models;

    protected function setUp(): void
    {
        $this->store = new InMemoryMetadataBlobStore();
        $metadata = new StoredMetadata($this->store);
        $this->models = new MetadataAuthenticatorModels($metadata, $metadata);
    }

    #[Test]
    public function theStatementNamesTheModelWithItsDescriptionAndItsIcon(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([
            MetadataBlobs::entry(self::AAGUID, description: 'YubiKey 5 Series', icon: AuthenticatorImages::PNG),
        ]));

        // When
        $model = $this->models->model(Uuid::fromString(self::AAGUID));

        // Then
        static::assertSame('YubiKey 5 Series', $model?->name);
        static::assertSame(MetadataAuthenticatorModels::SOURCE, $model->source);
        static::assertSame([AuthenticatorImages::PNG, AuthenticatorImages::PNG], [$model->logo?->light, $model->logo?->dark]);
    }

    #[Test]
    public function theCertificationIsTheOneTheStatusReportsLeaveTheModelWith(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(
            self::AAGUID,
            [AuthenticatorStatus::FIDO_CERTIFIED, AuthenticatorStatus::FIDO_CERTIFIED_L1, AuthenticatorStatus::UPDATE_AVAILABLE],
        )]));

        // When
        $model = $this->models->model(Uuid::fromString(self::AAGUID));

        // Then
        static::assertSame(FidoCertification::Level1, $model?->certification);
    }

    #[Test]
    public function aStatementWithoutIconNamesAModelWithoutLogo(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID, description: 'Security key')]));

        // When
        $model = $this->models->model(Uuid::fromString(self::AAGUID));

        // Then
        static::assertSame('Security key', $model?->name);
        static::assertNull($model->logo);
    }

    #[Test]
    public function anIconThatIsNotAnImageOfADataUrlIsNoLogo(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([
            MetadataBlobs::entry(self::AAGUID, description: 'Security key', icon: 'https://example.com/logo.png'),
        ]));

        // When
        $model = $this->models->model(Uuid::fromString(self::AAGUID));

        // Then
        static::assertSame('Security key', $model?->name);
        static::assertNull($model->logo);
    }

    #[Test]
    public function aStatementWithAnEmptyDescriptionNamesNothing(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID, description: '')]));

        // When / Then
        static::assertNull($this->models->model(Uuid::fromString(self::AAGUID)));
    }

    #[Test]
    public function anAaguidTheMetadataDoNotDescribeNamesNothing(): void
    {
        // Given
        $this->store->write('mds', MetadataBlobs::payload([MetadataBlobs::entry(self::AAGUID)]));

        // When / Then
        static::assertNull($this->models->model(Uuid::v4()));
    }
}
