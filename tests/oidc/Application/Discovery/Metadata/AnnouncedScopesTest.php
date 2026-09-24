<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use function array_map;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedScopes;
use Heidi\Oidc\Application\Discovery\ServedGrantTypes;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Tests\Fixture\FakeGrant;
use Heidi\Oidc\Tests\Fixture\ServedClaims;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3: "scopes_supported" is "openid", what the claims provider serves, and
 * "offline_access" where a grant makes good on it (OIDC Core §11).
 */
final class AnnouncedScopesTest extends TestCase
{
    #[Test]
    public function theyAreOpenidThenWhatTheClaimsProviderServes(): void
    {
        // Given
        $announced = self::announced([GrantType::AuthorizationCode, GrantType::RefreshToken]);

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

    /**
     * OIDC Core §11: "offline_access" asks for a refresh token, so a deployment that issues none does
     * not announce the scope that would promise one.
     */
    #[Test]
    public function aProviderWithoutTheRefreshTokenGrantAnnouncesNoOfflineAccess(): void
    {
        // Given
        $announced = self::announced([GrantType::AuthorizationCode]);

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone'], $members['scopes_supported']);
    }

    /**
     * OIDC Discovery §3: "openid" MUST be supported; it comes first whatever the claims provider lists,
     * and a scope listed twice is announced once.
     */
    #[Test]
    public function openidComesFirstAndOnce(): void
    {
        // Given
        $announced = new AnnouncedScopes(
            ServedClaims::of(['email', 'openid', 'email'], []),
            new ServedGrantTypes([new FakeGrant(GrantType::AuthorizationCode)]),
        );

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['openid', 'email'], $members['scopes_supported']);
    }

    /**
     * @param non-empty-list<GrantType> $grants
     */
    private static function announced(array $grants): AnnouncedScopes
    {
        return new AnnouncedScopes(
            new StandardClaimsProvider(),
            new ServedGrantTypes(array_map(static fn (GrantType $grant): FakeGrant => new FakeGrant($grant), $grants)),
        );
    }
}
