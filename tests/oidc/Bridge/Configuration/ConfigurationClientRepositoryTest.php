<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\Configuration;

use function array_map;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Domain\Credential\PasswordAlgorithm;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\Configuration\ClientDefinition;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
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
     * @var array<string, mixed>
     */
    private const array SPA = [
        'redirect_uris' => ['https://spa.example/callback'],
        'token_endpoint_auth_method' => 'none',
    ];

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * The acceptance of the issue: a client declared in configuration is found by id in its tenant, with
     * the defaults of a confidential client.
     */
    #[Test]
    public function aConfiguredClientIsFoundByIdInItsTenantWithTheDefaults(): void
    {
        // Given
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ], new NativePasswordHasher());

        // When
        $demo = self::find($repository, $this->tenant, 'oidc-demo');

        // Then
        static::assertSame('oidc-demo', $demo->clientId);
        static::assertSame('oidc-demo', $demo->name);
        static::assertTrue($demo->belongsTo($this->tenant));
        static::assertSame(TokenEndpointAuthMethod::ClientSecretBasic, $demo->tokenEndpointAuthMethod);
        static::assertFalse($demo->requiresConsent);
        static::assertTrue($demo->requiresPkce);
        static::assertTrue($demo->hasRedirectUri('https://demo.localhost/login/check'));
        static::assertTrue($demo->hasPostLogoutRedirectUri('https://demo.localhost/'));
        static::assertSame([GrantType::AuthorizationCode, GrantType::RefreshToken], $demo->grantTypes);
        static::assertSame(['openid', 'profile', 'email'], array_map(strval(...), $demo->allowedScopes));
    }

    /**
     * The secret is hashed by the real hasher.
     */
    #[Test]
    public function theSecretIsHashedByTheHasherOfTheCore(): void
    {
        // Given
        $hasher = new NativePasswordHasher();
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ], $hasher);

        // When
        $demo = self::find($repository, $this->tenant, 'oidc-demo');

        // Then
        static::assertNotNull($demo->secretHash);
        static::assertSame(PasswordAlgorithm::Argon2id, $demo->secretHash->algorithm);
        static::assertTrue($hasher->verify($demo->secretHash, Clients::SECRET));
        static::assertFalse($hasher->verify($demo->secretHash, 'not ' . Clients::SECRET));
    }

    /**
     * Every option of a definition is read.
     */
    #[Test]
    public function everyOptionOfADefinitionIsRead(): void
    {
        // Given
        $repository = $this->repository([
            'suite-second' => self::SUITE,
        ]);

        // When
        $suite = self::find($repository, $this->tenant, 'suite-second');

        // Then
        static::assertSame('Conformance suite, second client', $suite->name);
        static::assertSame(TokenEndpointAuthMethod::ClientSecretPost, $suite->tokenEndpointAuthMethod);
        static::assertTrue($suite->requiresConsent);
        static::assertTrue($suite->hasRedirectUri('https://localhost:8443/test/a/heidi/callback?dummy1=lorem&dummy2=ipsum'));
        static::assertFalse($suite->hasPostLogoutRedirectUri('https://localhost:8443/'));
        static::assertSame([GrantType::AuthorizationCode], $suite->grantTypes);
        static::assertSame(['openid', 'email'], array_map(strval(...), $suite->allowedScopes));
    }

    #[Test]
    public function aClientIsNotBuiltBeforeItIsLookedUp(): void
    {
        // Given
        $hasher = new FakePasswordHasher();

        // When
        $this->repository([
            'oidc-demo' => self::DEMO,
        ], $hasher);

        // Then
        static::assertSame(0, $hasher->hashed);
    }

    #[Test]
    public function aClientIsBuiltOnce(): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ], $hasher);

        // When
        $first = self::find($repository, $this->tenant, 'oidc-demo');
        $second = self::find($repository, $this->tenant, 'oidc-demo');

        // Then
        static::assertSame($first, $second);
        static::assertSame(1, $hasher->hashed);
    }

    /**
     * The integration may hold a tenant instance per request: each instance gets clients of its own,
     * pointing at it.
     */
    #[Test]
    public function anotherInstanceOfTheTenantGetsClientsOfItsOwn(): void
    {
        // Given
        $again = Fixtures::tenant();
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ]);

        // When
        $first = self::find($repository, $this->tenant, 'oidc-demo');
        $second = self::find($repository, $again, 'oidc-demo');

        // Then
        static::assertNotSame($first, $second);
        static::assertSame($this->tenant, $first->tenant);
        static::assertSame($again, $second->tenant);
        static::assertSame($second, self::find($repository, $again, 'oidc-demo'));
    }

    /**
     * The secret is still hashed once per process, whatever the tenant instances.
     */
    #[Test]
    public function theSecretIsHashedOncePerProcess(): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
            'spa' => self::SPA,
        ], $hasher);

        // When
        $first = self::find($repository, $this->tenant, 'oidc-demo');
        $second = self::find($repository, Fixtures::tenant(), 'oidc-demo');
        self::find($repository, $this->tenant, 'spa');

        // Then
        static::assertSame($first->secretHash, $second->secretHash);
        static::assertSame(1, $hasher->hashed);
    }

    /**
     * @param callable(self): Tenant $tenant
     */
    #[Test]
    #[DataProvider('provideLookupsThatFindNothing')]
    public function anUnknownIdOrAnotherTenantFindsNothing(callable $tenant, string $clientId): void
    {
        // Given
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ]);

        // When / Then
        static::assertNull($repository->findByClientId($tenant($this), $clientId));
    }

    /**
     * @return iterable<string, array{callable(self): Tenant, string}>
     */
    public static function provideLookupsThatFindNothing(): iterable
    {
        yield 'unknown id' => [
            static fn (self $test): Tenant => $test->tenant,
            'nobody',
        ];
        yield 'id in another case' => [
            static fn (self $test): Tenant => $test->tenant,
            'OIDC-DEMO',
        ];
        yield 'another tenant' => [
            static fn (self $test): Tenant => Fixtures::tenant('other', 'https://id.other.example'),
            'oidc-demo',
        ];
    }

    /**
     * RFC 6749 §2.1: a public client has no secret and identifies itself with "none".
     */
    #[Test]
    public function aPublicClientIsDeclaredWithNoneAndNoSecret(): void
    {
        // Given
        $repository = $this->repository([
            'spa' => self::SPA,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'spa');

        // Then
        static::assertTrue($client->isPublic());
        static::assertNull($client->secretHash);
    }

    /**
     * Decision 0008: requires_pkce is read like requires_consent, false only where the configuration says so.
     */
    #[Test]
    public function aConfidentialClientIsDeclaredWithoutThePkceRequirement(): void
    {
        // Given
        $repository = $this->repository([
            'legacy' => self::DEMO + [
                'requires_pkce' => false,
            ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'legacy');

        // Then
        static::assertFalse($client->requiresPkce);
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
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($reason);

        // When
        new ConfigurationClientRepository('acme', [
            'bad' => $definition,
        ], new FakePasswordHasher());
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
        yield 'requires_pkce as a string' => [$base + [
            'requires_pkce' => 'false',
        ], 'requires_pkce option of the client "bad" must be a boolean'];
        yield 'public client without the PKCE requirement (RFC 9700 §2.1.1)' => [[
            'redirect_uris' => ['https://rp.example/cb'],
            'token_endpoint_auth_method' => 'none',
            'requires_pkce' => false,
        ], 'is public and must use PKCE'];
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

    /**
     * RFC 6749 §2.1: a public client has no secret, so there is nothing to hash.
     */
    #[Test]
    public function aPublicDefinitionHasNoSecret(): void
    {
        // When / Then
        static::assertFalse(ClientDefinition::fromArray('spa', self::SPA)->hasSecret());
        static::assertTrue(ClientDefinition::fromArray('oidc-demo', self::DEMO)->hasSecret());
    }

    /**
     * Hashing the secret of a public definition is a programming error: the repository asks first.
     */
    #[Test]
    public function aPublicDefinitionRefusesToHashASecret(): void
    {
        // Given
        $definition = ClientDefinition::fromArray('spa', self::SPA);

        // Then
        $this->expectException(LogicException::class);

        // When
        $definition->hashSecret(new FakePasswordHasher());
    }

    /**
     * @param array<string, array<string, mixed>> $clients
     */
    private function repository(array $clients, ?PasswordHasherInterface $hasher = null): ConfigurationClientRepository
    {
        return new ConfigurationClientRepository($this->tenant->slug, $clients, $hasher ?? new FakePasswordHasher());
    }

    private static function find(ConfigurationClientRepository $repository, Tenant $tenant, string $clientId): Client
    {
        return $repository->findByClientId($tenant, $clientId) ?? static::fail(sprintf('The client "%s" should have been found.', $clientId));
    }
}
