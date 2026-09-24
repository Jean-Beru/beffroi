<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedGrants;
use Heidi\Oidc\Application\Token\ServedGrants;
use Heidi\Oidc\Tests\Fixture\FakeGrant;
use Heidi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3, RFC 8414 §2: "grant_types_supported" is what the token endpoint serves, the grants
 * tagged into it.
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
     * RFC 6749 §4.5, RFC 8414 §2: a grant nobody wrote a line of this provider for is announced because
     * it is wired, under the name it gives itself.
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
