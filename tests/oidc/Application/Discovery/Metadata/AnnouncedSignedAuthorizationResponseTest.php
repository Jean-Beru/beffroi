<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedSignedAuthorizationResponse;
use Beffroi\Oidc\Port\ServedResponseModesInterface;
use Beffroi\Oidc\Tests\Fixture\ServedModes;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * JARM §3: what a signed authorization response is signed with, and what it may be encrypted with, are
 * announced where a mode that signs the answer is wired and nowhere else: a deployment that signs no
 * answer has none to sign or to encrypt.
 */
final class AnnouncedSignedAuthorizationResponseTest extends TestCase
{
    #[Test]
    public function aWiredSignedModeAnnouncesWhatSignsAndEncryptsTheAnswer(): void
    {
        // Given
        $announced = self::announced(ServedModes::signedToo());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'authorization_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
                'authorization_encryption_alg_values_supported' => ['ECDH-ES+A256KW', 'RSA-OAEP-256'],
                'authorization_encryption_enc_values_supported' => ['A256GCM'],
            ],
            $members,
        );
    }

    #[Test]
    public function aDeploymentWithoutASignedModeAnnouncesNothingOfOne(): void
    {
        // Given
        $announced = self::announced(ServedModes::queryAndFormPost());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame([], $members);
    }

    private static function announced(ServedResponseModesInterface $modes): AnnouncedSignedAuthorizationResponse
    {
        return new AnnouncedSignedAuthorizationResponse(
            $modes,
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()),
        );
    }
}
