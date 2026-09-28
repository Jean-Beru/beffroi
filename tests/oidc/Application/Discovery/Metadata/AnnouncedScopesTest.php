<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Claims\StandardClaimsProvider;
use Heidi\Oidc\Application\Client\RegisteredClients;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedScopes;
use Heidi\Oidc\Application\Token\ServedGrants;
use Heidi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakeClaimsProvider;
use Heidi\Oidc\Tests\Fixture\FakeRefreshTokenIssuingGrant;
use Heidi\Oidc\Tests\Fixture\FakeRefreshTokenSpendingGrant;
use Heidi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3: "scopes_supported" is "openid", what the wired claims providers serve, what the
 * clients of the tenant registered, and "offline_access" where the wired grants make good on it
 * (OIDC Core §11).
 */
final class AnnouncedScopesTest extends TestCase
{
    #[Test]
    public function theyAreOpenidThenWhatTheClaimsProviderServes(): void
    {
        // Given
        $announced = new AnnouncedScopes(new StandardClaimsProvider(), Grants::served(), new RegisteredClients([new InMemoryClientRepository()]));

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
            new RegisteredClients([new InMemoryClientRepository()]),
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
            new RegisteredClients([new InMemoryClientRepository()]),
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
            FakeClaimsProvider::of(['email', 'openid', 'email'], []),
            new ServedGrants([new FakeRefreshTokenIssuingGrant(Grants::authorizationCode())]),
            new RegisteredClients([new InMemoryClientRepository()]),
        );

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['openid', 'email'], $members['scopes_supported']);
    }

    /**
     * Issue #98: what a tenant announces is read from its clients, so a scope one of them registered is
     * a scope of that tenant, each named once however many clients registered it.
     */
    #[Test]
    public function itAnnouncesTheScopesTheClientsOfTheTenantRegistered(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, allowedScopes: self::billing()));
        $clients->save(Clients::public($tenant, 'other-spa', allowedScopes: self::billing()));
        $announced = new AnnouncedScopes(new StandardClaimsProvider(), Grants::served(), new RegisteredClients([$clients]));

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame(
            ['openid', 'profile', 'email', 'address', 'phone', 'billing.read', 'billing.write', 'offline_access'],
            $members['scopes_supported'],
        );
    }

    /**
     * The scopes of one tenant are no business of another: two tenants whose clients registered
     * different scopes announce different documents.
     */
    #[Test]
    public function itAnnouncesNoScopeOfAnotherTenant(): void
    {
        // Given
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public(Fixtures::tenant(), allowedScopes: self::billing()));
        $announced = new AnnouncedScopes(new StandardClaimsProvider(), Grants::served(), new RegisteredClients([$clients]));

        // When
        $members = $announced->metadata(Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone', 'offline_access'], $members['scopes_supported']);
    }

    /**
     * The scope of an API stands for no claim, and a registration is the only thing that says it exists:
     * it is announced, as a resource a client registered is (RFC 9728 §4), and a typo is announced with
     * it rather than granted in silence. What a client that registers itself may name is held to what
     * this document already carries, where such a registration is read.
     */
    #[Test]
    public function aScopeNoClaimsProviderServesIsAnnouncedBecauseAClientRegisteredIt(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, allowedScopes: new Scopes([new Scope('billing.read')])));
        $announced = new AnnouncedScopes(FakeClaimsProvider::of([], []), Grants::served(), new RegisteredClients([$clients]));

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame(['openid', 'billing.read', 'offline_access'], $members['scopes_supported']);
    }

    /**
     * OIDC Core §11: "offline_access" is the one scope a registration does not put in the document. A
     * client registered for it on a deployment whose grants cannot make it good would have the document
     * promise a refresh token the token endpoint would refuse.
     */
    #[Test]
    public function aClientRegisteredForOfflineAccessDoesNotAnnounceItWhereNoGrantMakesItGood(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, allowedScopes: new Scopes([Scope::openid(), Scope::offlineAccess()])));
        $announced = new AnnouncedScopes(
            new StandardClaimsProvider(),
            new ServedGrants([new FakeRefreshTokenIssuingGrant(Grants::authorizationCode())]),
            new RegisteredClients([$clients]),
        );

        // When
        $members = $announced->metadata($tenant);

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone'], $members['scopes_supported']);
    }

    /**
     * Two scopes an API of the deployment is protected by, which no claims provider serves.
     */
    private static function billing(): Scopes
    {
        return new Scopes([Scope::openid(), new Scope('billing.read'), new Scope('billing.write')]);
    }
}
