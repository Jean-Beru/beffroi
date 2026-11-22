<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedGrants;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Tests\Fixture\FakeGrant;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3, RFC 8414 §2
 */
final class AnnouncedGrantsTest extends TestCase
{
    #[Test]
    public function theyAreTheGrantsTheTokenEndpointServes(): void
    {
        // Given
        $announced = new AnnouncedGrants(Grants::served());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
            ],
            $members,
        );
    }

    /**
     * RFC 6749 §4.5, RFC 8414 §2
     */
    #[Test]
    public function aGrantTheProviderGainsIsAnnouncedByBeingWired(): void
    {
        // Given
        $announced = new AnnouncedGrants(new ServedGrants([new FakeGrant(Grants::invented())]));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['urn:example:params:oauth:grant-type:invented'], $members['grant_types_supported']);
    }
}
