<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\Configuration;

use function array_map;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\FakePasswordHasher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function sprintf;

final class ConfigurationClientRepositoryTest extends TestCase
{
    /**
     * @var array<string, mixed>
     */
    private const array DEMO = [
        'secret' => Clients::SECRET,
        'redirect_uris' => ['https://demo.localhost/login/check'],
        'post_logout_redirect_uris' => ['https://demo.localhost/'],
        'token_endpoint_auth_method' => 'client_secret_basic',
        'requires_consent' => false,
    ];

    /**
     * @var array<string, mixed>
     */
    private const array SUITE = [
        'name' => 'Conformance suite, second client',
        'secret' => Clients::SECRET,
        'redirect_uris' => ['https://localhost:8443/test/a/heidi/callback', 'https://localhost:8443/test/a/heidi/callback?dummy1=lorem&dummy2=ipsum'],
        'grant_types' => ['authorization_code'],
        'allowed_scopes' => ['openid', 'email'],
        'token_endpoint_auth_method' => 'client_secret_post',
    ];

    /**
     * The acceptance of the issue: two clients declared in configuration are found by id in a tenant, with
     * the secret hashed by the real hasher.
     */
    #[Test]
    public function twoConfiguredClientsAreFoundByIdInTheirTenant(): void
    {
        $tenant = Fixtures::tenant();
        $hasher = new NativePasswordHasher();
        $repository = new ConfigurationClientRepository($tenant, [
            'oidc-demo' => self::DEMO,
            'suite-second' => self::SUITE,
        ], $hasher);

        $demo = self::find($repository, $tenant, 'oidc-demo');
        $suite = self::find($repository, $tenant, 'suite-second');

        static::assertSame('oidc-demo', $demo->clientId);
        static::assertSame('oidc-demo', $demo->name);
        static::assertTrue($demo->belongsTo($tenant));
        static::assertSame(TokenEndpointAuthMethod::ClientSecretBasic, $demo->tokenEndpointAuthMethod);
        static::assertFalse($demo->requiresConsent);
        static::assertTrue($demo->hasRedirectUri('https://demo.localhost/login/check'));
        static::assertTrue($demo->hasPostLogoutRedirectUri('https://demo.localhost/'));
        static::assertSame([GrantType::AuthorizationCode, GrantType::RefreshToken], $demo->grantTypes);
        static::assertSame(['openid', 'profile', 'email'], array_map(strval(...), $demo->allowedScopes));
        static::assertNotNull($demo->secretHash);
        static::assertSame(PasswordAlgorithm::Argon2id, $demo->secretHash->algorithm);
        static::assertTrue($hasher->verify($demo->secretHash, Clients::SECRET));
        static::assertFalse($hasher->verify($demo->secretHash, 'not ' . Clients::SECRET));

        static::assertSame('Conformance suite, second client', $suite->name);
        static::assertSame(TokenEndpointAuthMethod::ClientSecretPost, $suite->tokenEndpointAuthMethod);
        static::assertTrue($suite->requiresConsent);
        static::assertTrue($suite->hasRedirectUri('https://localhost:8443/test/a/heidi/callback?dummy1=lorem&dummy2=ipsum'));
        static::assertFalse($suite->hasPostLogoutRedirectUri('https://localhost:8443/'));
        static::assertSame([GrantType::AuthorizationCode], $suite->grantTypes);
        static::assertSame(['openid', 'email'], array_map(strval(...), $suite->allowedScopes));
    }

    #[Test]
    public function aClientIsBuiltOnceAndOnlyWhenLookedUp(): void
    {
        $tenant = Fixtures::tenant();
        $hasher = new FakePasswordHasher();
        $repository = new ConfigurationClientRepository($tenant, [
            'oidc-demo' => self::DEMO,
            'suite-second' => self::SUITE,
        ], $hasher);

        $first = self::find($repository, $tenant, 'oidc-demo');
        $second = self::find($repository, $tenant, 'oidc-demo');

        static::assertSame($first, $second);
    }

    #[Test]
    public function anUnknownIdOrAnotherTenantFindsNothing(): void
    {
        $tenant = Fixtures::tenant();
        $repository = new ConfigurationClientRepository($tenant, [
            'oidc-demo' => self::DEMO,
        ], new FakePasswordHasher());

        static::assertNull($repository->findByClientId($tenant, 'nobody'));
        static::assertNull($repository->findByClientId($tenant, 'OIDC-DEMO'));
        static::assertNull($repository->findByClientId(Fixtures::tenant('other', 'https://id.other.example'), 'oidc-demo'));
    }

    /**
     * RFC 6749 §2.1: a public client has no secret and identifies itself with "none".
     */
    #[Test]
    public function aPublicClientIsDeclaredWithNoneAndNoSecret(): void
    {
        $tenant = Fixtures::tenant();
        $repository = new ConfigurationClientRepository($tenant, [
            'spa' => [
                'redirect_uris' => ['https://spa.example/callback'],
                'token_endpoint_auth_method' => 'none',
            ],
        ], new FakePasswordHasher());

        $client = self::find($repository, $tenant, 'spa');

        static::assertTrue($client->isPublic());
        static::assertNull($client->secretHash);
    }

    /**
     * A wrong definition fails when the repository is built, not when the client first shows up.
     *
     * @param array<string, mixed> $definition
     */
    #[Test]
    #[DataProvider('provideInvalidDefinitions')]
    public function aWrongDefinitionFailsAtBoot(array $definition, string $reason): void
    {
        try {
            new ConfigurationClientRepository(Fixtures::tenant(), [
                'bad' => $definition,
            ], new FakePasswordHasher());
            static::fail('The definition should have been rejected.');
        } catch (InvalidArgumentException $exception) {
            static::assertStringContainsString($reason, $exception->getMessage());
        }
    }

    private static function find(ConfigurationClientRepository $repository, Tenant $tenant, string $clientId): Client
    {
        return $repository->findByClientId($tenant, $clientId) ?? static::fail(sprintf('The client "%s" should have been found.', $clientId));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideInvalidDefinitions(): iterable
    {
        $base = [
            'secret' => Clients::SECRET,
            'redirect_uris' => ['https://rp.example/cb'],
        ];

        yield 'unknown key' => [$base + [
            'insecure_allow_plain_pkce' => true,
        ], 'unknown keys: insecure_allow_plain_pkce'];
        yield 'secret not a string' => [[
            'secret' => 12345,
        ] + $base, 'must be a string'];
        yield 'secret too short' => [[
            'secret' => 'short',
        ] + $base, 'at least 32 visible ASCII characters'];
        yield 'secret with a non-ASCII character' => [[
            'secret' => 'é' . Clients::SECRET,
        ] + $base, 'at least 32 visible ASCII characters'];
        yield 'confidential without a secret' => [[
            'redirect_uris' => ['https://rp.example/cb'],
        ], 'needs a secret'];
        yield 'public with a secret' => [$base + [
            'token_endpoint_auth_method' => 'none',
        ], 'cannot hold a secret'];
        yield 'unknown authentication method' => [$base + [
            'token_endpoint_auth_method' => 'private_key_jwt',
        ], 'must be one of: client_secret_basic, client_secret_post, none'];
        yield 'authentication method not a string' => [$base + [
            'token_endpoint_auth_method' => true,
        ], 'must be one of'];
        yield 'requires_consent as a string' => [$base + [
            'requires_consent' => 'false',
        ], 'must be a boolean'];
        yield 'name not a string' => [$base + [
            'name' => ['x'],
        ], 'name of the client "bad" must be a string'];
        yield 'redirect_uris not a list' => [[
            'redirect_uris' => 'https://rp.example/cb',
        ] + $base, 'redirect_uris option of the client "bad" must be a list of strings'];
        yield 'redirect_uris with a non-string' => [[
            'redirect_uris' => [42],
        ] + $base, 'redirect_uris option of the client "bad" must be a list of strings'];
        yield 'redirect URI with a fragment' => [[
            'redirect_uris' => ['https://rp.example/cb#x'],
        ] + $base, 'fragment'];
        yield 'no redirect URI' => [[
            'redirect_uris' => [],
        ] + $base, 'at least one redirect URI'];
        yield 'post logout URI over plain http' => [$base + [
            'post_logout_redirect_uris' => ['http://rp.example/'],
        ], 'HTTPS'];
        yield 'no grant type' => [$base + [
            'grant_types' => [],
        ], 'at least one grant type'];
        yield 'refresh_token alone' => [$base + [
            'grant_types' => ['refresh_token'],
        ], 'requires authorization_code'];
        yield 'unknown grant' => [$base + [
            'grant_types' => ['implicit'],
        ], 'must be one of: authorization_code, refresh_token'];
        yield 'invalid scope' => [$base + [
            'allowed_scopes' => ['openid profile'],
        ], 'scope token'];
        yield 'no scope' => [$base + [
            'allowed_scopes' => [],
        ], 'at least one scope'];
        yield 'empty name' => [$base + [
            'name' => '',
        ], 'has a name'];
        yield 'unknown signing algorithm' => [$base + [
            'id_token_signed_response_alg' => 'HS256',
        ], 'must be one of: RS256'];
    }
}
