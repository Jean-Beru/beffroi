<?php

declare(strict_types=1);

namespace Beffroi\Saml\Tests\Unit\Domain\Upstream;

use function array_keys;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * S-8, S-42
 */
final class AcceptedUpstreamMetadataTest extends TestCase
{
    /**
     * S-8, S-42
     */
    #[Test]
    public function theDocumentIsSealedInTheFamilyOfItsTable(): void
    {
        // When
        $fields = AcceptedUpstreamMetadata::classifiedFields();

        // Then
        static::assertEquals(new Sealed('saml_upstream_identity_provider'), $fields['document']);
    }

    /**
     * S-8
     */
    #[Test]
    public function everyFieldOfTheRowIsClassified(): void
    {
        // When / Then
        static::assertSame(
            ['id', 'tenant', 'entityId', 'validUntil', 'acceptedAt', 'document'],
            array_keys(AcceptedUpstreamMetadata::classifiedFields()),
        );
    }
}
