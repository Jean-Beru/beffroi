<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedIdToken;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3: what the provider signs an ID token with, and what a client may have it encrypted
 * to itself with (issue #165).
 */
final class AnnouncedIdTokenTest extends TestCase
{
    #[Test]
    public function itAnnouncesWhatSignsAnIdTokenAndWhatEncryptsOne(): void
    {
        // Given
        $announced = new AnnouncedIdToken(new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'id_token_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
                'id_token_encryption_alg_values_supported' => ['ECDH-ES+A256KW', 'RSA-OAEP-256'],
                'id_token_encryption_enc_values_supported' => ['A256GCM'],
            ],
            $members,
        );
    }

    /**
     * A deployment nobody encrypts to still signs: it announces what signs an ID token and nothing about
     * encrypting one.
     */
    #[Test]
    public function aDeploymentThatEncryptsNothingStillAnnouncesWhatSigns(): void
    {
        // Given
        $announced = new AnnouncedIdToken(new AnnouncedAlgorithms(Algorithms::all(), Algorithms::noKeyEncryption(), Algorithms::noContentEncryption()));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'id_token_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
            ],
            $members,
        );
    }
}
