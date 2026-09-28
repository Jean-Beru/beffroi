<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Client\RegisteredClients;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedScopes;
use Heidi\Oidc\Application\Scope\OfferedScopes;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3: "scopes_supported" is every scope the tenant hands out tokens for, read where that
 * set is assembled (`OfferedScopes`) so that what is announced and what a registration is held to are
 * one set and not two that must agree.
 */
final class AnnouncedScopesTest extends TestCase
{
    #[Test]
    public function itAnnouncesTheScopesTheTenantOffers(): void
    {
        // Given
        $announced = new AnnouncedScopes(
            new OfferedScopes(new StandardClaimsProvider(), Grants::served(), new RegisteredClients([new InMemoryClientRepository()])),
        );

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'scopes_supported' => ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'],
            ],
            $members,
        );
    }
}
