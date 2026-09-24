<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedUserInfo;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §5.3.2 and OIDC Discovery §3: a client may have the UserInfo answer signed by the tenant,
 * and encrypted to itself, with the algorithms the provider signs and encrypts everything else with.
 */
final class AnnouncedUserInfoTest extends TestCase
{
    #[Test]
    public function itAnnouncesWhatSignsAUserInfoAnswerAndWhatEncryptsOne(): void
    {
        // Given
        $announced = new AnnouncedUserInfo(new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()));

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
}
