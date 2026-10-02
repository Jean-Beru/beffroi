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
 * OIDC Discovery §3 and decision 0010: the classes the policy of the tenant can actually prove with the
 * methods the deployment wired, and the kinds of subject identifier the provider assigns one of.
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
     * OIDC Core §8: the kinds are the resolvers that are wired, so a deployment that wires the pairwise one
     * announces it by the fact of assigning it, and one that does not announces "public" alone. The two
     * modules that judge a sector skip themselves unless the document names "pairwise", so this line is what
     * makes them run at all.
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

    /**
     * A deployment that wired a password alone proves the classes a password satisfies, and announces no
     * other: the document says what the provider does.
     */
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
