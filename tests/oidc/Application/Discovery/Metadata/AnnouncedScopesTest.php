<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedScopes;
use Heidi\Oidc\Application\Token\ServedGrants;
use Heidi\Oidc\Tests\Fixture\FakeRefreshTokenIssuingGrant;
use Heidi\Oidc\Tests\Fixture\FakeRefreshTokenSpendingGrant;
use Heidi\Oidc\Tests\Fixture\Grants;
use Heidi\Oidc\Tests\Fixture\ServedClaims;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3: "scopes_supported" is "openid", what the claims provider serves, and
 * "offline_access" where the wired grants make good on it (OIDC Core §11).
 */
final class AnnouncedScopesTest extends TestCase
{
    #[Test]
    public function theyAreOpenidThenWhatTheClaimsProviderServes(): void
    {
        // Given
        $announced = new AnnouncedScopes(new StandardClaimsProvider(), Grants::served());

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
     * OIDC Core §11: "offline_access" asks for a refresh token, so a deployment wired with no grant that
     * spends one does not announce the scope that would promise one.
     */
    #[Test]
    public function aProviderThatSpendsNoRefreshTokenAnnouncesNoOfflineAccess(): void
    {
        // Given
        $announced = new AnnouncedScopes(
            new StandardClaimsProvider(),
            new ServedGrants([new FakeRefreshTokenIssuingGrant(Grants::authorizationCode())]),
        );

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone'], $members['scopes_supported']);
    }

    /**
     * OIDC Core §11: a refresh token nothing mints is a promise the token endpoint cannot keep either.
     */
    #[Test]
    public function aProviderThatIssuesNoRefreshTokenAnnouncesNoOfflineAccess(): void
    {
        // Given
        $announced = new AnnouncedScopes(
            new StandardClaimsProvider(),
            new ServedGrants([new FakeRefreshTokenSpendingGrant(Grants::refreshToken())]),
        );

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
            new ServedGrants([new FakeRefreshTokenIssuingGrant(Grants::authorizationCode())]),
        );

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['openid', 'email'], $members['scopes_supported']);
    }
}
