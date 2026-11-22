<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\HeldSigning;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedUserInfo;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §5.3.2, OIDC Discovery §3
 */
final class AnnouncedUserInfoTest extends TestCase
{
    #[Test]
    public function itAnnouncesWhatSignsAUserInfoAnswerAndWhatEncryptsOne(): void
    {
        // Given
        $announced = new AnnouncedUserInfo(
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()),
            HeldSigning::everyAlgorithm(),
        );

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'userinfo_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
                'userinfo_encryption_alg_values_supported' => ['ECDH-ES+A256KW', 'RSA-OAEP-256'],
                'userinfo_encryption_enc_values_supported' => ['A256GCM'],
            ],
            $members,
        );
    }

    #[Test]
    public function anAlgorithmTheTenantHoldsNoActiveKeyForSignsNoUserInfoAnswer(): void
    {
        // Given
        $announced = new AnnouncedUserInfo(
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::noKeyEncryption(), Algorithms::noContentEncryption()),
            HeldSigning::of([Algorithms::es256()]),
        );

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['userinfo_signing_alg_values_supported' => ['ES256']], $members);
    }
}
