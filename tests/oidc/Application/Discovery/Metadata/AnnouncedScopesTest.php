<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedScopes;
use Beffroi\Oidc\Application\Scope\OfferedScopes;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationDeclaredScopes;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3
 */
final class AnnouncedScopesTest extends TestCase
{
    #[Test]
    public function itAnnouncesTheScopesTheTenantOffers(): void
    {
        // Given
        $announced = new AnnouncedScopes(
            new OfferedScopes(
                new StandardClaimsProvider(),
                Grants::served(),
                new RegisteredClients([new InMemoryClientRepository()]),
                new ConfigurationDeclaredScopes(Fixtures::tenant()->slug),
            ),
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
