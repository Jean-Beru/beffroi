<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use function array_map;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    #[Test]
    public function aConfidentialClientHoldsAHashedSecret(): void
    {
        // Given
        $hash = new FakePasswordHasher()
            ->hash(Clients::SECRET);

        // When
        $client = Clients::confidential(Fixtures::tenant(), $hash);

        // Then
        static::assertFalse($client->isPublic());
        static::assertSame($hash, $client->secretHash);
        static::assertSame(TokenEndpointAuthMethod::ClientSecretBasic, $client->tokenEndpointAuthMethod);
    }

    #[Test]
    public function aClientBelongsToItsTenantOnly(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $client = Clients::public($tenant);

        // When / Then
        static::assertTrue($client->belongsTo($tenant));
        static::assertFalse($client->belongsTo(Fixtures::tenant('other')));
    }

    #[Test]
    public function aClientAllowsItsRegisteredGrantsOnly(): void
    {
        // Given
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // When / Then
        static::assertTrue($client->allowsGrant(GrantType::AuthorizationCode));
        static::assertTrue($client->allowsGrant(GrantType::RefreshToken));
        static::assertFalse(Clients::public(Fixtures::tenant())->allowsGrant(GrantType::RefreshToken));
    }

    #[Test]
    public function aClientAllowsItsRegisteredScopesOnly(): void
    {
        // Given
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // When / Then
        static::assertSame(['openid', 'profile', 'email'], array_map(strval(...), $client->allowedScopes));
        static::assertTrue($client->allowsScope(Scope::openid()));
        static::assertTrue($client->allowsScope(new Scope('email')));
        static::assertFalse($client->allowsScope(new Scope('offline_access')));
    }

    #[Test]
    public function aClientRequiresConsentUnlessRegisteredOtherwise(): void
    {
        // When
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // Then
        static::assertTrue($client->requiresConsent);
    }

    /**
     * RFC 6749 §2.1: a public client has no secret.
     */
    #[Test]
    public function aPublicClientHasNoSecret(): void
    {
        // When
        $client = Clients::public(Fixtures::tenant());

        // Then
        static::assertTrue($client->isPublic());
        static::assertNull($client->secretHash);
        static::assertSame([GrantType::AuthorizationCode], $client->grantTypes);
        static::assertEquals([Scope::openid()], $client->allowedScopes);
    }

    /**
     * RFC 6749 §3.1.2.3: exact match of the redirect URI.
     */
    #[Test]
    #[DataProvider('provideRedirectUris')]
    public function itMatchesItsRedirectUrisExactly(string $uri, bool $registered): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant());

        // When / Then
        static::assertSame($registered, $client->hasRedirectUri($uri));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function provideRedirectUris(): iterable
    {
        yield 'as registered' => ['https://spa.example/callback', true];
        yield 'trailing slash' => ['https://spa.example/callback/', false];
        yield 'different case' => ['https://spa.example/Callback', false];
    }

    /**
     * A client identifier is unique within its tenant: two registrations of the same identifier in two
     * tenants are two clients.
     */
    #[Test]
    public function itEqualsTheSameRegistrationOfItsTenant(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $client = Clients::public($tenant);

        // When / Then
        static::assertTrue($client->equals(Clients::public($tenant)));
        static::assertFalse($client->equals(Clients::public($tenant, 'another')));
        static::assertFalse($client->equals(Clients::public(Fixtures::tenant('other', 'https://id.other.example'))));
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2: the post-logout URI is a registered value, matched exactly too.
     */
    #[Test]
    #[DataProvider('providePostLogoutRedirectUris')]
    public function itMatchesItsPostLogoutRedirectUrisExactly(string $uri, bool $registered): void
    {
        // Given
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // When / Then
        static::assertSame($registered, $client->hasPostLogoutRedirectUri($uri));
    }

    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function providePostLogoutRedirectUris(): iterable
    {
        yield 'as registered' => ['https://demo.localhost/', true];
        yield 'without the trailing slash' => ['https://demo.localhost', false];
        yield 'a redirect URI' => ['https://demo.localhost/login/check', false];
    }

    #[Test]
    public function aClientWithoutPostLogoutRedirectUriMatchesNone(): void
    {
        // Given
        $client = Clients::public(Fixtures::tenant());

        // When / Then
        static::assertFalse($client->hasPostLogoutRedirectUri('https://spa.example/'));
    }

    #[Test]
    public function itKeepsEachUriGrantAndScopeOnce(): void
    {
        // When
        $client = new Client(
            Fixtures::tenant(),
            'twice',
            'Twice',
            TokenEndpointAuthMethod::None,
            null,
            [new RedirectUri('https://rp.example/cb'), new RedirectUri('https://rp.example/cb'), new RedirectUri('https://rp.example/cb2')],
            [new RedirectUri('https://rp.example/'), new RedirectUri('https://rp.example/')],
            [GrantType::AuthorizationCode, GrantType::AuthorizationCode],
            [new Scope('openid'), new Scope('openid'), new Scope('email')],
        );

        // Then
        static::assertCount(2, $client->redirectUris);
        static::assertCount(1, $client->postLogoutRedirectUris);
        static::assertSame([GrantType::AuthorizationCode], $client->grantTypes);
        static::assertSame(['openid', 'email'], array_map(strval(...), $client->allowedScopes));
    }

    /**
     * @param callable(Tenant): Client $build
     */
    #[Test]
    #[DataProvider('provideInvalidClients')]
    public function itRefusesAnInconsistentRegistration(callable $build, string $reason): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($reason);

        // When
        $build(Fixtures::tenant());
    }

    /**
     * @return iterable<string, array{callable(Tenant): Client, string}>
     */
    public static function provideInvalidClients(): iterable
    {
        $hash = new FakePasswordHasher()
            ->hash(Clients::SECRET);
        $uris = [new RedirectUri('https://rp.example/cb')];

        yield 'empty client id' => [
            static fn (Tenant $tenant): Client => new Client($tenant, '', 'Name', TokenEndpointAuthMethod::None, null, $uris),
            'visible ASCII',
        ];
        yield 'client id with a trailing space' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo ', 'Name', TokenEndpointAuthMethod::None, null, $uris),
            'visible ASCII',
        ];
        yield 'client id with a control character' => [
            static fn (Tenant $tenant): Client => new Client($tenant, "de\tmo", 'Name', TokenEndpointAuthMethod::None, null, $uris),
            'visible ASCII',
        ];
        yield 'client id beyond ASCII (RFC 6749 appendix A.1)' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'démo', 'Name', TokenEndpointAuthMethod::None, null, $uris),
            'visible ASCII',
        ];
        yield 'empty name' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', '', TokenEndpointAuthMethod::None, null, $uris),
            'has a name',
        ];
        yield 'client_secret_basic without a secret' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', TokenEndpointAuthMethod::ClientSecretBasic, null, $uris),
            'needs a secret',
        ];
        yield 'client_secret_post without a secret' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', TokenEndpointAuthMethod::ClientSecretPost, null, $uris),
            'needs a secret',
        ];
        yield 'none with a secret (RFC 6749 §2.1)' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', TokenEndpointAuthMethod::None, $hash, $uris),
            'cannot hold a secret',
        ];
        yield 'no redirect URI (RFC 6749 §3.1.2.2)' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', TokenEndpointAuthMethod::None, null, []),
            'at least one redirect URI',
        ];
        yield 'no grant type' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', TokenEndpointAuthMethod::None, null, $uris, [], []),
            'at least one grant type',
        ];
        yield 'refresh_token alone' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', TokenEndpointAuthMethod::None, null, $uris, [], [GrantType::RefreshToken]),
            'requires authorization_code',
        ];
        yield 'no scope' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', TokenEndpointAuthMethod::None, null, $uris, [], [GrantType::AuthorizationCode], []),
            'at least one scope',
        ];
    }

    #[Test]
    #[DataProvider('provideAuthenticationMethods')]
    public function theAuthenticationMethodsSayWhetherTheyUseASecret(TokenEndpointAuthMethod $method, bool $usesSecret): void
    {
        // When / Then
        static::assertSame($usesSecret, $method->usesSecret());
    }

    /**
     * @return iterable<string, array{TokenEndpointAuthMethod, bool}>
     */
    public static function provideAuthenticationMethods(): iterable
    {
        yield 'client_secret_basic' => [TokenEndpointAuthMethod::ClientSecretBasic, true];
        yield 'client_secret_post' => [TokenEndpointAuthMethod::ClientSecretPost, true];
        yield 'none' => [TokenEndpointAuthMethod::None, false];
    }
}
