<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedDpop;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 9449 §5.1: what the provider verifies a DPoP proof with is what it is wired to verify a JWS with.
 */
final class AnnouncedDpopTest extends TestCase
{
    #[Test]
    public function itAnnouncesWhatAProofMayBeSignedWith(): void
    {
        // Given
        $announced = new AnnouncedDpop(new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'dpop_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
            ],
            $members,
        );
    }
}
