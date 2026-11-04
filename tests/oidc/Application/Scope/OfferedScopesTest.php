<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Scope;

use function array_map;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\StandardClaimsProvider;
use Beffroi\Oidc\Application\Client\RegisteredClients;
use Beffroi\Oidc\Application\Scope\OfferedScopes;
use Beffroi\Oidc\Application\Token\ServedGrants;
use Beffroi\Oidc\Bridge\Configuration\ConfigurationDeclaredScopes;
use Beffroi\Oidc\Bridge\InMemory\InMemoryClientRepository;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeClaimsProvider;
use Beffroi\Oidc\Tests\Fixture\FakeRefreshTokenIssuingGrant;
use Beffroi\Oidc\Tests\Fixture\FakeRefreshTokenSpendingGrant;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class OfferedScopesTest extends TestCase
{
    #[Test]
    public function theyAreOpenidThenWhatTheClaimsProviderServes(): void
    {
        // Given
        $offered = new OfferedScopes(new StandardClaimsProvider(), Grants::served(), new RegisteredClients([new InMemoryClientRepository()]), self::declared());

        // When
        $members = self::values($offered, Fixtures::tenant());

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone', 'offline_access'], $members);
    }

    /**
     * OIDC Core §11
     */
    #[Test]
    public function aProviderThatSpendsNoRefreshTokenAnnouncesNoOfflineAccess(): void
    {
        // Given
        $offered = new OfferedScopes(
            new StandardClaimsProvider(),
            new ServedGrants([new FakeRefreshTokenIssuingGrant(Grants::authorizationCode())]),
            new RegisteredClients([new InMemoryClientRepository()]),
            self::declared(),
        );

        // When
        $members = self::values($offered, Fixtures::tenant());

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone'], $members);
    }

    /**
     * OIDC Core §11
     */
    #[Test]
    public function aProviderThatIssuesNoRefreshTokenAnnouncesNoOfflineAccess(): void
    {
        // Given
        $offered = new OfferedScopes(
            new StandardClaimsProvider(),
            new ServedGrants([new FakeRefreshTokenSpendingGrant(Grants::refreshToken())]),
            new RegisteredClients([new InMemoryClientRepository()]),
            self::declared(),
        );

        // When
        $members = self::values($offered, Fixtures::tenant());

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone'], $members);
    }

    /**
     * OIDC Discovery §3
     */
    #[Test]
    public function openidComesFirstAndOnce(): void
    {
        // Given
        $offered = new OfferedScopes(
            FakeClaimsProvider::of(['email', 'openid', 'email'], []),
            new ServedGrants([new FakeRefreshTokenIssuingGrant(Grants::authorizationCode())]),
            new RegisteredClients([new InMemoryClientRepository()]),
            self::declared(),
        );

        // When
        $members = self::values($offered, Fixtures::tenant());

        // Then
        static::assertSame(['openid', 'email'], $members);
    }

    #[Test]
    public function itAnnouncesTheScopesTheClientsOfTheTenantRegistered(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, allowedScopes: self::billing()));
        $clients->save(Clients::public($tenant, 'other-spa', allowedScopes: self::billing()));
        $offered = new OfferedScopes(new StandardClaimsProvider(), Grants::served(), new RegisteredClients([$clients]), self::declared());

        // When
        $members = self::values($offered, $tenant);

        // Then
        static::assertSame(
            ['openid', 'profile', 'email', 'address', 'phone', 'billing.read', 'billing.write', 'offline_access'],
            $members,
        );
    }

    #[Test]
    public function itAnnouncesNoScopeOfAnotherTenant(): void
    {
        // Given
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public(Fixtures::tenant(), allowedScopes: self::billing()));
        $offered = new OfferedScopes(new StandardClaimsProvider(), Grants::served(), new RegisteredClients([$clients]), self::declared());

        // When
        $members = self::values($offered, Fixtures::tenant('other', 'https://id.other.example'));

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone', 'offline_access'], $members);
    }

    #[Test]
    public function aScopeNoClaimsProviderServesIsAnnouncedBecauseAClientRegisteredIt(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, allowedScopes: new Scopes([new Scope('billing.read')])));
        $offered = new OfferedScopes(FakeClaimsProvider::of([], []), Grants::served(), new RegisteredClients([$clients]), self::declared());

        // When
        $members = self::values($offered, $tenant);

        // Then
        static::assertSame(['openid', 'billing.read', 'offline_access'], $members);
    }

    #[Test]
    public function theScopesTheDeploymentDeclaresAreOfferedBeforeAnyClientRegistersThem(): void
    {
        // Given
        $offered = new OfferedScopes(
            new StandardClaimsProvider(),
            Grants::served(),
            new RegisteredClients([new InMemoryClientRepository()]),
            self::declared(['invoices.read', 'invoices.pay']),
        );

        // When
        $members = self::values($offered, Fixtures::tenant());

        // Then
        static::assertSame(
            ['openid', 'profile', 'email', 'address', 'phone', 'invoices.read', 'invoices.pay', 'offline_access'],
            $members,
        );
    }

    #[Test]
    public function aScopeTheDeploymentDeclaresAndAClientRegistersIsOfferedOnce(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, allowedScopes: self::billing()));
        $offered = new OfferedScopes(
            FakeClaimsProvider::of([], []),
            Grants::served(),
            new RegisteredClients([$clients]),
            self::declared(['billing.write']),
        );

        // When
        $members = self::values($offered, $tenant);

        // Then
        static::assertSame(['openid', 'billing.write', 'billing.read', 'offline_access'], $members);
    }

    /**
     * OIDC Core §11
     */
    #[Test]
    public function aClientRegisteredForOfflineAccessDoesNotAnnounceItWhereNoGrantMakesItGood(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $clients = new InMemoryClientRepository();
        $clients->save(Clients::public($tenant, allowedScopes: new Scopes([Scope::openid(), Scope::offlineAccess()])));
        $offered = new OfferedScopes(
            new StandardClaimsProvider(),
            new ServedGrants([new FakeRefreshTokenIssuingGrant(Grants::authorizationCode())]),
            new RegisteredClients([$clients]),
            self::declared(),
        );

        // When
        $members = self::values($offered, $tenant);

        // Then
        static::assertSame(['openid', 'profile', 'email', 'address', 'phone'], $members);
    }

    /**
     * @return list<string>
     */
    private static function values(OfferedScopes $offered, Tenant $tenant): array
    {
        return array_map(static fn (Scope $scope): string => $scope->value, $offered->scopesOfferedIn($tenant));
    }

    /**
     * @param list<string> $scopes
     */
    private static function declared(array $scopes = []): ConfigurationDeclaredScopes
    {
        return new ConfigurationDeclaredScopes(Fixtures::tenant()->slug, $scopes);
    }

    private static function billing(): Scopes
    {
        return new Scopes([Scope::openid(), new Scope('billing.read'), new Scope('billing.write')]);
    }
}
