<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldSigning;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedIdToken;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3
 */
final class AnnouncedIdTokenTest extends TestCase
{
    #[Test]
    public function itAnnouncesWhatSignsAnIdTokenAndWhatEncryptsOne(): void
    {
        // Given
        $announced = new AnnouncedIdToken(
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()),
            HeldSigning::everyAlgorithm(),
        );

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

    #[Test]
    public function aDeploymentThatEncryptsNothingStillAnnouncesWhatSigns(): void
    {
        // Given
        $announced = new AnnouncedIdToken(
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::noKeyEncryption(), Algorithms::noContentEncryption()),
            HeldSigning::everyAlgorithm(),
        );

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

    #[Test]
    public function anAlgorithmTheTenantHoldsNoActiveKeyForSignsNoIdToken(): void
    {
        // Given
        $announced = new AnnouncedIdToken(
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::noKeyEncryption(), Algorithms::noContentEncryption()),
            HeldSigning::of([Algorithms::rs256()]),
        );

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['id_token_signing_alg_values_supported' => ['RS256']], $members);
    }
}
