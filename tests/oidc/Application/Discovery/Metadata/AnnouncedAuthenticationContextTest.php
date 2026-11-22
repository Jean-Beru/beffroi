<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedAuthenticationContext;
use Beffroi\Oidc\Tests\Fixture\Logins;
use PHPUnit\Framework\Attributes\Test;
use Beffroi\Oidc\Tests\Fixture\Subjects;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3, Decision 0010
 */
final class AnnouncedAuthenticationContextTest extends TestCase
{
    #[Test]
    public function theyAreTheClassesTheWiredMethodsCanProve(): void
    {
        // Given
        $announced = new AnnouncedAuthenticationContext(Logins::passwordAndPasskey(), Subjects::ofAProvider());

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
     * OIDC Core §8
     */
    #[Test]
    public function theSubjectTypesAreTheKindsTheProviderIsWiredWith(): void
    {
        // Given
        $announced = new AnnouncedAuthenticationContext(Logins::passwordAndPasskey(), Subjects::bothKinds());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['public', 'pairwise'], $members['subject_types_supported']);
    }

    #[Test]
    public function aDeploymentThatOnlyTakesAPasswordAnnouncesWhatAPasswordProves(): void
    {
        // Given
        $announced = new AnnouncedAuthenticationContext(Logins::passwordOnly(), Subjects::ofAProvider());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['1'], $members['acr_values_supported']);
    }
}
