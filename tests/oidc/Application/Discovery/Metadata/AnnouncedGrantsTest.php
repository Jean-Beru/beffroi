<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedGrants;
use Heidi\Oidc\Application\Discovery\ServedGrantTypes;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Tests\Fixture\FakeGrant;
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
        $announced = new AnnouncedGrants(new ServedGrantTypes([new FakeGrant(GrantType::AuthorizationCode), new FakeGrant(GrantType::RefreshToken)]));

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
     * RFC 8414 §2: a grant wired twice is announced once.
     */
    #[Test]
    public function aGrantWiredTwiceIsAnnouncedOnce(): void
    {
        // Given
        $announced = new AnnouncedGrants(new ServedGrantTypes([new FakeGrant(GrantType::AuthorizationCode), new FakeGrant(GrantType::AuthorizationCode)]));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['authorization_code'], $members['grant_types_supported']);
    }
}
