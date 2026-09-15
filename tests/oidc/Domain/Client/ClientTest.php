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
    public function aConfidentialClientHoldsAHashedSecretAndClosedLists(): void
    {
        $tenant = Fixtures::tenant();
        $hash = new FakePasswordHasher()
            ->hash(Clients::SECRET);

        $client = Clients::confidential($tenant, $hash);

        static::assertTrue($client->belongsTo($tenant));
        static::assertFalse($client->belongsTo(Fixtures::tenant('other')));
        static::assertFalse($client->isPublic());
        static::assertSame($hash, $client->secretHash);
        static::assertSame(TokenEndpointAuthMethod::ClientSecretBasic, $client->tokenEndpointAuthMethod);
        static::assertTrue($client->requiresConsent);
        static::assertTrue($client->allowsGrant(GrantType::AuthorizationCode));
        static::assertTrue($client->allowsGrant(GrantType::RefreshToken));
        static::assertTrue($client->allowsScope(Scope::openid()));
        static::assertTrue($client->allowsScope(new Scope('email')));
        static::assertFalse($client->allowsScope(new Scope('offline_access')));
        static::assertSame(['openid', 'profile', 'email'], array_map(strval(...), $client->allowedScopes));
    }

    /**
     * RFC 6749 §2.1: a public client has no secret; RFC 6749 §3.1.2.3: exact match of the redirect URI.
     */
    #[Test]
    public function aPublicClientHasNoSecretAndMatchesItsRedirectUrisExactly(): void
    {
        $client = Clients::public(Fixtures::tenant());

        static::assertTrue($client->isPublic());
        static::assertNull($client->secretHash);
        static::assertSame([GrantType::AuthorizationCode], $client->grantTypes);
        static::assertFalse($client->allowsGrant(GrantType::RefreshToken));
        static::assertEquals([Scope::openid()], $client->allowedScopes);
        static::assertTrue($client->hasRedirectUri('https://spa.example/callback'));
        static::assertFalse($client->hasRedirectUri('https://spa.example/callback/'));
        static::assertFalse($client->hasRedirectUri('https://spa.example/Callback'));
        static::assertFalse($client->hasPostLogoutRedirectUri('https://spa.example/'));
    }

    /**
     * OIDC RP-Initiated Logout 1.0 §2: the post-logout URI is a registered value, matched exactly too.
     */
    /**
     * A client identifier is unique within its tenant: two registrations of the same identifier in two
     * tenants are two clients.
     */
    #[Test]
    public function itEqualsTheSameRegistrationOfItsTenant(): void
    {
        $tenant = Fixtures::tenant();
        $client = Clients::public($tenant);

        static::assertTrue($client->equals(Clients::public($tenant)));
        static::assertFalse($client->equals(Clients::public($tenant, 'another')));
        static::assertFalse($client->equals(Clients::public(Fixtures::tenant('other', 'https://id.other.example'))));
    }

    #[Test]
    public function itKnowsItsPostLogoutRedirectUris(): void
    {
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        static::assertTrue($client->hasPostLogoutRedirectUri('https://demo.localhost/'));
        static::assertFalse($client->hasPostLogoutRedirectUri('https://demo.localhost'));
        static::assertFalse($client->hasPostLogoutRedirectUri('https://demo.localhost/login/check'));
    }

    #[Test]
    public function itKeepsEachUriGrantAndScopeOnce(): void
    {
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
        try {
            $build(Fixtures::tenant());
            static::fail('The client should have been rejected.');
        } catch (InvalidArgumentException $exception) {
            static::assertStringContainsString($reason, $exception->getMessage());
        }
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
    public function theAuthenticationMethodsSayWhetherTheyUseASecret(): void
    {
        static::assertTrue(TokenEndpointAuthMethod::ClientSecretBasic->usesSecret());
        static::assertTrue(TokenEndpointAuthMethod::ClientSecretPost->usesSecret());
        static::assertFalse(TokenEndpointAuthMethod::None->usesSecret());
    }
}
