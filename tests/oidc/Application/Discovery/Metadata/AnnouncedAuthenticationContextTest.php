<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedAuthenticationContext;
use Heidi\Oidc\Tests\Fixture\Logins;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3 and decision 0010: the classes the policy of the tenant can actually prove with the
 * methods the deployment wired, and the only subject type the provider mints.
 */
final class AnnouncedAuthenticationContextTest extends TestCase
{
    #[Test]
    public function theyAreTheClassesTheWiredMethodsCanProve(): void
    {
        // Given
        $announced = new AnnouncedAuthenticationContext(Logins::passwordAndPasskey());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'acr_values_supported' => ['phrh', 'phr', '2', '1'],
                'subject_types_supported' => ['public'],
            ],
            $members,
        );
    }

    /**
     * A deployment that wired a password alone proves the classes a password satisfies, and announces no
     * other: the document says what the provider does.
     */
    #[Test]
    public function aDeploymentThatOnlyTakesAPasswordAnnouncesWhatAPasswordProves(): void
    {
        // Given
        $announced = new AnnouncedAuthenticationContext(Logins::passwordOnly());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['1'], $members['acr_values_supported']);
    }
}
