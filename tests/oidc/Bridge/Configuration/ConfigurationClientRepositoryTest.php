<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Bridge\Configuration;

use function array_column;
use function array_map;
use Heidi\Core\Bridge\Password\NativePasswordHasher;
use Heidi\Core\Bridge\Password\Algorithm\Argon2id;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Port\PasswordHasherInterface;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Bridge\Configuration\ClientDefinition;
use Heidi\Oidc\Bridge\Configuration\ConfigurationClientRepository;
use Heidi\Oidc\Bridge\Pki\PkiFrameworkCertificateReader;
use Heidi\Oidc\Domain\Client\AccessTokenFormat;
use Heidi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Exception\LogicException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Methods;
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

    /**
     * A client that authenticates with a key of its own (OIDC Core §9), publishing its JWK Set inline.
     *
     * @var array<string, mixed>
     */
    private const array KEY_CLIENT = [
        'redirect_uris' => ['https://key.example/callback'],
        'token_endpoint_auth_method' => 'private_key_jwt',
        'jwks' => [
            'keys' => [[
                'kty' => 'EC',
                'crv' => 'P-256',
                'kid' => 'one',
                'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
            ]],
        ],
    ];

    private Tenant $tenant;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
    }

    /**
     * RFC 7591 §2: a client that authenticates with a key of its own publishes its JWK Set inline.
     */
    #[Test]
    public function aClientMayPublishItsKeysInline(): void
    {
        // Given
        $repository = $this->repository([
            'key-client' => self::KEY_CLIENT,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'key-client');

        // Then
        static::assertSame('private_key_jwt', $client->authenticationMethod->name());
        static::assertInstanceOf(ClientJwks::class, $client->jwks);
        static::assertSame(['one'], array_column($client->jwks->keys, 'kid'));
        static::assertNull($client->jwksUri);
    }

    /**
     * RFC 7591 §2: or behind a "jwks_uri", read as every other URI a client registers.
     */
    #[Test]
    public function aClientMayPublishItsKeysBehindAJwksUri(): void
    {
        // Given
        $repository = $this->repository([
            'key-client' => [
                'redirect_uris' => ['https://key.example/callback'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks_uri' => 'https://key.example/jwks',
            ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'key-client');

        // Then
        static::assertSame('https://key.example/jwks', $client->jwksUri?->value);
        static::assertNull($client->jwks);
    }

    /**
     * RFC 8705 §2.1.2: a client recognised by its certificate registers one of the five values, each one
     * under the metadata name of the specification.
     */
    #[Test]
    #[DataProvider('provideCertificateRegistrations')]
    public function aClientRegistersWhatNamesItInItsCertificate(string $name, string $value): void
    {
        // Given
        $repository = $this->repository([
            'mtls-client' => [
                'redirect_uris' => ['https://mtls.example/callback'],
                'token_endpoint_auth_method' => 'tls_client_auth',
                $name => $value,
            ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'mtls-client');

        // Then
        static::assertSame($name, $client->certificateIdentity?->name());
    }

    /**
     * RFC 8705 §2.1.2 asks for a predictable treatment of distinguished names: what a deployment
     * registers is written back by the reader that will read the name of the certificate, once, at boot.
     */
    #[Test]
    public function aRegisteredDistinguishedNameIsWrittenTheWayTheOneOfACertificateIs(): void
    {
        // Given
        $repository = $this->repository([
            'mtls-client' => [
                'redirect_uris' => ['https://mtls.example/callback'],
                'token_endpoint_auth_method' => 'tls_client_auth',
                'tls_client_auth_subject_dn' => 'C=FR,O=Heidi Test,CN=heidi mtls client',
            ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'mtls-client');

        // Then
        static::assertInstanceOf(SubjectDistinguishedName::class, $client->certificateIdentity);
        static::assertSame('c=FR,o=Heidi Test,cn=heidi mtls client', $client->certificateIdentity->distinguishedName);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideCertificateRegistrations(): iterable
    {
        yield 'tls_client_auth_subject_dn' => ['tls_client_auth_subject_dn', 'cn=heidi mtls client'];

        yield 'tls_client_auth_san_dns' => ['tls_client_auth_san_dns', 'client.example.com'];

        yield 'tls_client_auth_san_uri' => ['tls_client_auth_san_uri', 'https://client.example.com/callback'];

        yield 'tls_client_auth_san_ip' => ['tls_client_auth_san_ip', '198.51.100.7'];

        yield 'tls_client_auth_san_email' => ['tls_client_auth_san_email', 'ops@client.example.com'];
    }

    /**
     * OIDC Core §9: "client_secret_jwt" computes a MAC with the registered secret, so the secret is kept
     * and not hashed; that is the method's own cost and the reason FAPI 2.0 §5.2.2 takes none.
     */
    #[Test]
    public function aClientThatSignsWithItsSecretKeepsTheSecretAndNotAHash(): void
    {
        // Given
        $hasher = new FakePasswordHasher();
        $repository = $this->repository([
            'mac-client' => [
                'secret' => Clients::SECRET,
                'redirect_uris' => ['https://mac.example/callback'],
                'token_endpoint_auth_method' => 'client_secret_jwt',
            ],
        ], $hasher);

        // When
        $client = self::find($repository, $this->tenant, 'mac-client');

        // Then
        static::assertInstanceOf(SharedClientSecret::class, $client->secret);
        static::assertSame(Clients::SECRET, $client->secret->value);
        static::assertSame(0, $hasher->hashed);
    }

    /**
     * A client that names no method takes the first wired one (issue #98).
     */
    #[Test]
    public function aClientThatNamesNoMethodTakesTheFirstWiredOne(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => [
                'secret' => Clients::SECRET,
                'redirect_uris' => ['https://demo.localhost/login/check'],
            ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertSame('client_secret_basic', $client->authenticationMethod->name());
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
        static::assertSame('client_secret_basic', $demo->authenticationMethod->name());
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
        static::assertInstanceOf(HashedClientSecret::class, $demo->secret);
        static::assertSame(Argon2id::NAME, $demo->secret->hash->algorithm->name());
        static::assertTrue($hasher->verify($demo->secret->hash, Clients::SECRET));
        static::assertFalse($hasher->verify($demo->secret->hash, 'not ' . Clients::SECRET));
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
        static::assertSame('client_secret_post', $suite->authenticationMethod->name());
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
        static::assertSame($first->secret, $second->secret);
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
        static::assertNull($client->secret);
    }

    /**
     * Decision 0008: requires_pkce is read like requires_consent, false only where the configuration says so.
     */
    #[Test]
    public function aConfidentialClientIsDeclaredWithoutThePkceRequirement(): void
    {
        // Given
        $repository = $this->repository([
            'legacy' => self::DEMO
                + [
                    'requires_pkce' => false,
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'legacy');

        // Then
        static::assertFalse($client->requiresPkce);
    }

    /**
     * RFC 9126 §6: a client declares that the only way it starts an authorization request is by pushing
     * it, which is what FAPI 2.0 asks of one; a client that says nothing starts an ordinary one.
     */
    #[Test]
    public function aClientIsDeclaredAsOneThatOnlyPushesItsRequests(): void
    {
        // Given
        $repository = $this->repository([
            'fapi' => self::DEMO
                + [
                    'require_pushed_authorization_requests' => true,
                ],
            'demo' => self::DEMO,
        ]);

        // When
        $fapi = self::find($repository, $this->tenant, 'fapi');

        // Then
        static::assertTrue($fapi->requiresPushedAuthorizationRequests);
        static::assertFalse(self::find($repository, $this->tenant, 'demo')->requiresPushedAuthorizationRequests);
    }

    /**
     * RFC 9126 §5, issue #98: the document says a request must be pushed when every client declared for
     * the tenant says so, read where the clients are declared and nowhere else.
     *
     * @param array<string, array<string, mixed>> $clients
     */
    #[Test]
    #[DataProvider('provideDeclarationsOfTheRequirement')]
    public function theTenantRequiresAPushedRequestWhenEveryDeclaredClientDoes(array $clients, bool $required): void
    {
        // Given
        $repository = $this->repository($clients);

        // When / Then
        static::assertSame($required, $repository->requiresPushedAuthorizationRequests($this->tenant));
    }

    /**
     * @return iterable<string, array{array<string, array<string, mixed>>, bool}>
     */
    public static function provideDeclarationsOfTheRequirement(): iterable
    {
        $pushing = self::DEMO
        + [
            'require_pushed_authorization_requests' => true,
        ];
        yield 'every client pushes' => [
            [
                'fapi' => $pushing,
                'other' => $pushing,
            ],
            true,
        ];
        yield 'one client may still start an ordinary request' => [
            [
                'fapi' => $pushing,
                'demo' => self::DEMO,
            ],
            false,
        ];
        yield 'no client at all' => [[], false];
    }

    /**
     * The clients of another tenant are not this tenant's, and neither is what they require.
     */
    #[Test]
    public function anotherTenantRequiresNothingOfTheClientsDeclaredHere(): void
    {
        // Given
        $repository = $this->repository([
            'fapi' => self::DEMO
                + [
                    'require_pushed_authorization_requests' => true,
                ],
        ]);

        // When / Then
        static::assertFalse($repository->requiresPushedAuthorizationRequests(Fixtures::tenant('other', 'https://id.other.example')));
    }

    /**
     * Back-Channel Logout 1.0 §2.2: a client says where to be told a session ended, and whether it reads
     * the "sid" of the token.
     */
    #[Test]
    public function aClientDeclaresWhereItIsToldASessionEnded(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => self::DEMO
                + [
                    'backchannel_logout_uri' => 'https://demo.localhost/backchannel-logout',
                    'backchannel_logout_session_required' => true,
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertSame('https://demo.localhost/backchannel-logout', (string) $client->backChannelLogoutUri);
        static::assertTrue($client->backChannelLogoutSessionRequired);
    }

    /**
     * Back-Channel Logout 1.0 §2.2: a client that declares nothing is told nothing.
     */
    #[Test]
    public function aClientIsToldOfNoLogoutUntilItDeclaresAUri(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => self::DEMO,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertNull($client->backChannelLogoutUri);
        static::assertFalse($client->backChannelLogoutSessionRequired);
    }

    /**
     * Front-Channel Logout 1.0 §2 and §3: a client says where the logout page loads it, and whether it
     * reads the "iss" and the "sid" on that URI.
     */
    #[Test]
    public function aClientDeclaresWhereTheLogoutPageLoadsIt(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => self::DEMO
                + [
                    'frontchannel_logout_uri' => 'https://demo.localhost/frontchannel-logout',
                    'frontchannel_logout_session_required' => true,
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertSame('https://demo.localhost/frontchannel-logout', (string) $client->frontChannelLogoutUri);
        static::assertTrue($client->frontChannelLogoutSessionRequired);
    }

    /**
     * Front-Channel Logout 1.0 §3: a client that declares nothing is not loaded.
     */
    #[Test]
    public function aClientIsLoadedByNoLogoutPageUntilItDeclaresAUri(): void
    {
        // Given
        $repository = $this->repository([
            'demo' => self::DEMO,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'demo');

        // Then
        static::assertNull($client->frontChannelLogoutUri);
        static::assertFalse($client->frontChannelLogoutSessionRequired);
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
        new ConfigurationClientRepository(
            'acme',
            [
                'bad' => $definition,
            ],
            new FakePasswordHasher(),
            Algorithms::all(),
            Methods::all(),
            new PkiFrameworkCertificateReader(),
            Algorithms::keyEncryption(),
            Algorithms::contentEncryption(),
        );
    }

    /**
     * OIDC Registration §2 and JARM §3: what a client registers for each of the three documents it
     * receives is read back on it, the algorithm it is signed with and the pair it is encrypted with.
     */
    #[Test]
    public function aClientIsReadBackWithWhatItRegisteredForEachDocument(): void
    {
        // Given
        $repository = $this->repository([
            'key-client' => self::KEY_CLIENT
                + [
                    'id_token_signed_response_alg' => 'ES256',
                    'id_token_encrypted_response_alg' => 'ECDH-ES+A256KW',
                    'id_token_encrypted_response_enc' => 'A256GCM',
                    'userinfo_signed_response_alg' => 'ES256',
                    'authorization_encrypted_response_alg' => 'ECDH-ES+A256KW',
                    'authorization_encrypted_response_enc' => 'A256GCM',
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'key-client');

        // Then
        static::assertSame('ES256', $client->idToken->signature?->name());
        static::assertSame('ECDH-ES+A256KW', $client->idToken->encryption?->algorithm->name());
        static::assertSame('A256GCM', $client->idToken->encryption?->method->name());
        static::assertTrue($client->userInfo->isSigned);
        static::assertFalse($client->userInfo->isEncrypted());
        static::assertTrue($client->authorizationResponse->isEncrypted());
    }

    /**
     * A client that registers nothing receives what every client receives: its ID tokens and its signed
     * authorization responses signed with what the provider signs with, its UserInfo answer as JSON.
     */
    #[Test]
    public function aClientThatRegistersNothingTakesTheOrdinaryShapes(): void
    {
        // Given
        $repository = $this->repository([
            'oidc-demo' => self::DEMO,
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'oidc-demo');

        // Then
        static::assertSame('RS256', $client->idToken->signature?->name());
        static::assertFalse($client->idToken->isEncrypted());
        static::assertTrue($client->userInfo->isPlain());
        static::assertFalse($client->authorizationResponse->isEncrypted());
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

        yield 'unknown key' => [
            $base
                + [
                    'insecure_allow_plain_pkce' => true,
                ],
            'unknown keys: insecure_allow_plain_pkce',
        ];
        yield 'an encryption algorithm without a content encryption' => [
            self::KEY_CLIENT
                + [
                    'id_token_encrypted_response_alg' => 'ECDH-ES+A256KW',
                ],
            'registers id_token_encrypted_response_alg without id_token_encrypted_response_enc',
        ];
        yield 'a content encryption without an encryption algorithm' => [
            self::KEY_CLIENT
                + [
                    'userinfo_encrypted_response_enc' => 'A256GCM',
                ],
            'registers userinfo_encrypted_response_enc without userinfo_encrypted_response_alg',
        ];
        yield 'an encryption algorithm the provider is not wired with' => [
            self::KEY_CLIENT
                + [
                    'authorization_encrypted_response_alg' => 'RSA1_5',
                    'authorization_encrypted_response_enc' => 'A256GCM',
                ],
            'The authorization_encrypted_response_alg option of the client "bad" must be one of: ECDH-ES+A256KW, RSA-OAEP-256.',
        ];
        yield 'a content encryption the provider is not wired with' => [
            self::KEY_CLIENT
                + [
                    'id_token_encrypted_response_alg' => 'ECDH-ES+A256KW',
                    'id_token_encrypted_response_enc' => 'A128CBC-HS256',
                ],
            'The id_token_encrypted_response_enc option of the client "bad" must be one of: A256GCM.',
        ];
        yield 'an encrypted response and no key published at all' => [
            $base
                + [
                    'id_token_encrypted_response_alg' => 'ECDH-ES+A256KW',
                    'id_token_encrypted_response_enc' => 'A256GCM',
                ],
            'registers an encrypted response, which is addressed to a key of the client, and therefore publishes its keys',
        ];
        yield 'an encrypted response and no key it can be addressed to' => [
            self::KEY_CLIENT
                + [
                    'id_token_encrypted_response_alg' => 'RSA-OAEP-256',
                    'id_token_encrypted_response_enc' => 'A256GCM',
                ],
            'publishes no key it can be addressed to',
        ];
        yield 'an encrypted response and only a signing key' => [
            [
                'redirect_uris' => ['https://key.example/callback'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => [
                    'keys' => [[
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'kid' => 'one',
                        'use' => 'sig',
                        'x' => 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
                        'y' => 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
                    ]],
                ],
                'userinfo_encrypted_response_alg' => 'ECDH-ES+A256KW',
                'userinfo_encrypted_response_enc' => 'A256GCM',
            ],
            'publishes no key it can be addressed to',
        ];
        yield 'secret not a string' => [
            [
                'secret' => 12345,
            ] + $base,
            'must be a string',
        ];
        yield 'secret too short' => [
            [
                'secret' => 'short',
            ] + $base,
            'at least 32 visible ASCII characters',
        ];
        yield 'secret with a non-ASCII character' => [
            [
                'secret' => 'é' . Clients::SECRET,
            ] + $base,
            'at least 32 visible ASCII characters',
        ];
        yield 'confidential without a secret' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            'needs a secret',
        ];
        yield 'public with a secret' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'none',
                ],
            'cannot hold a secret',
        ];
        yield 'an authentication method nothing is wired with' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'smoke_signal',
                ],
            'must be one of: client_secret_basic, client_secret_post, private_key_jwt, client_secret_jwt, tls_client_auth, self_signed_tls_client_auth, none',
        ];
        yield 'two of the values of RFC 8705 §2.1.2' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'tls_client_auth',
                    'tls_client_auth_subject_dn' => 'cn=client',
                    'tls_client_auth_san_dns' => 'client.example.com',
                ],
            'registers exactly one of the values of RFC 8705 section 2.1.2',
        ];
        yield 'a subject distinguished name that is not one' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'tls_client_auth',
                    'tls_client_auth_subject_dn' => 'heidi mtls client',
                ],
            'must be a distinguished name of RFC 4514',
        ];
        yield 'a certificate name that is not a string' => [
            $base
                + [
                    'token_endpoint_auth_method' => 'tls_client_auth',
                    'tls_client_auth_san_dns' => 42,
                ],
            'tls_client_auth_san_dns option of the client "bad" must be a string',
        ];
        yield 'authentication method not a string' => [
            $base
                + [
                    'token_endpoint_auth_method' => true,
                ],
            'token_endpoint_auth_method option of the client "bad" must be a string',
        ];
        yield 'private_key_jwt without keys (RFC 7591 §2)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'private_key_jwt',
            ],
            'publishes its keys in "jwks" or behind a "jwks_uri"',
        ];
        yield 'jwks and jwks_uri together (RFC 7591 §2)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => [
                    'keys' => [[
                        'kty' => 'EC',
                        'crv' => 'P-256',
                        'x' => 'x',
                        'y' => 'y',
                    ]],
                ],
                'jwks_uri' => 'https://rp.example/jwks',
            ],
            'either inline in "jwks" or behind a "jwks_uri", never both',
        ];
        yield 'jwks not a JWK Set' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => [
                    'keys' => 'no',
                ],
            ],
            'object with a "keys" member',
        ];
        yield 'a symmetric key in jwks (RFC 8725 §3.5)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'private_key_jwt',
                'jwks' => [
                    'keys' => [[
                        'kty' => 'oct',
                        'k' => 'AAAA',
                    ]],
                ],
            ],
            'symmetric key in a JWK Set is refused',
        ];
        yield 'requires_consent as a string' => [
            $base
                + [
                    'requires_consent' => 'false',
                ],
            'must be a boolean',
        ];
        yield 'requires_pkce as a string' => [
            $base
                + [
                    'requires_pkce' => 'false',
                ],
            'requires_pkce option of the client "bad" must be a boolean',
        ];
        yield 'require_pushed_authorization_requests as a string' => [
            $base
                + [
                    'require_pushed_authorization_requests' => 'true',
                ],
            'require_pushed_authorization_requests option of the client "bad" must be a boolean',
        ];
        yield 'public client without the PKCE requirement (RFC 9700 §2.1.1)' => [
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'token_endpoint_auth_method' => 'none',
                'requires_pkce' => false,
            ],
            'is public and must use PKCE',
        ];
        yield 'name not a string' => [
            $base
                + [
                    'name' => ['x'],
                ],
            'name of the client "bad" must be a string',
        ];
        yield 'redirect_uris not a list' => [
            [
                'redirect_uris' => 'https://rp.example/cb',
            ] + $base,
            'redirect_uris option of the client "bad" must be a list of strings',
        ];
        yield 'redirect_uris with a non-string' => [
            [
                'redirect_uris' => [42],
            ] + $base,
            'redirect_uris option of the client "bad" must be a list of strings',
        ];
        yield 'redirect URI with a fragment' => [
            [
                'redirect_uris' => ['https://rp.example/cb#x'],
            ] + $base,
            'fragment',
        ];
        yield 'no redirect URI' => [
            [
                'redirect_uris' => [],
            ] + $base,
            'at least one redirect URI',
        ];
        yield 'post logout URI over plain http' => [
            $base
                + [
                    'post_logout_redirect_uris' => ['http://rp.example/'],
                ],
            'HTTPS',
        ];
        yield 'no grant type' => [
            $base
                + [
                    'grant_types' => [],
                ],
            'at least one grant type',
        ];
        yield 'refresh_token alone' => [
            $base
                + [
                    'grant_types' => ['refresh_token'],
                ],
            'requires authorization_code',
        ];
        yield 'unknown grant' => [
            $base
                + [
                    'grant_types' => ['implicit'],
                ],
            'must be one of: authorization_code, refresh_token',
        ];
        yield 'invalid scope' => [
            $base
                + [
                    'allowed_scopes' => ['openid profile'],
                ],
            'scope token',
        ];
        yield 'no scope' => [
            $base
                + [
                    'allowed_scopes' => [],
                ],
            'at least one scope',
        ];
        yield 'empty name' => [
            $base
                + [
                    'name' => '',
                ],
            'has a name',
        ];
        yield 'unknown signing algorithm' => [
            $base
                + [
                    'id_token_signed_response_alg' => 'HS256',
                ],
            'must be one of: RS256, PS256, ES256, EdDSA',
        ];
        yield 'unknown request object algorithm' => [
            $base
                + [
                    'request_object_signing_alg' => 'HS256',
                ],
            'must be "none" or one of: RS256, PS256, ES256, EdDSA',
        ];
        yield 'request object algorithm without a key to verify it' => [
            $base
                + [
                    'request_object_signing_alg' => 'ES256',
                ],
            'registers a request_object_signing_alg',
        ];
        yield 'request_uri over plain http' => [
            $base
                + [
                    'request_uris' => ['http://rp.example/request.jwt'],
                ],
            'HTTPS',
        ];
        yield 'request_uris as a string' => [
            $base
                + [
                    'request_uris' => 'https://rp.example/request.jwt',
                ],
            'request_uris option of the client "bad" must be a list of strings',
        ];
        yield 'back-channel logout URI over plain http' => [
            $base
                + [
                    'backchannel_logout_uri' => 'http://rp.example/backchannel-logout',
                ],
            'HTTPS',
        ];
        yield 'back-channel logout URI with a fragment' => [
            $base
                + [
                    'backchannel_logout_uri' => 'https://rp.example/backchannel-logout#x',
                ],
            'fragment',
        ];
        yield 'back-channel logout URI not a string' => [
            $base
                + [
                    'backchannel_logout_uri' => ['https://rp.example/backchannel-logout'],
                ],
            'backchannel_logout_uri option of the client "bad" must be a string',
        ];
        yield 'backchannel_logout_session_required as a string' => [
            $base
                + [
                    'backchannel_logout_uri' => 'https://rp.example/backchannel-logout',
                    'backchannel_logout_session_required' => 'true',
                ],
            'backchannel_logout_session_required option of the client "bad" must be a boolean',
        ];
        yield 'a "sid" required with nowhere to send it' => [
            $base
                + [
                    'backchannel_logout_session_required' => true,
                ],
            'registers no backchannel_logout_uri',
        ];
        yield 'front-channel logout URI over plain http' => [
            $base
                + [
                    'frontchannel_logout_uri' => 'http://rp.example/frontchannel-logout',
                ],
            'HTTPS',
        ];
        yield 'front-channel logout URI with a fragment' => [
            $base
                + [
                    'frontchannel_logout_uri' => 'https://rp.example/frontchannel-logout#x',
                ],
            'fragment',
        ];
        yield 'front-channel logout URI not a string' => [
            $base
                + [
                    'frontchannel_logout_uri' => ['https://rp.example/frontchannel-logout'],
                ],
            'frontchannel_logout_uri option of the client "bad" must be a string',
        ];
        yield 'frontchannel_logout_session_required as a string' => [
            $base
                + [
                    'frontchannel_logout_uri' => 'https://rp.example/frontchannel-logout',
                    'frontchannel_logout_session_required' => 'true',
                ],
            'frontchannel_logout_session_required option of the client "bad" must be a boolean',
        ];
        yield 'an "iss" and a "sid" required on no URI' => [
            $base
                + [
                    'frontchannel_logout_session_required' => true,
                ],
            'registers no frontchannel_logout_uri',
        ];
    }

    /**
     * RFC 6749 §2.1: a public client has no secret, so there is nothing to hash.
     */
    #[Test]
    public function aPublicDefinitionHasNoSecret(): void
    {
        // When / Then
        static::assertFalse(
            ClientDefinition::fromArray(
                'spa',
                self::SPA,
                Algorithms::all(),
                Methods::all(),
                new PkiFrameworkCertificateReader(),
                Algorithms::keyEncryption(),
                Algorithms::contentEncryption(),
            )->hasSecret(),
        );
        static::assertTrue(
            ClientDefinition::fromArray(
                'oidc-demo',
                self::DEMO,
                Algorithms::all(),
                Methods::all(),
                new PkiFrameworkCertificateReader(),
                Algorithms::keyEncryption(),
                Algorithms::contentEncryption(),
            )->hasSecret(),
        );
    }

    /**
     * Keeping the secret of a public definition is a programming error: the repository asks first.
     */
    #[Test]
    public function aPublicDefinitionRefusesToKeepASecret(): void
    {
        // Given
        $definition = ClientDefinition::fromArray(
            'spa',
            self::SPA,
            Algorithms::all(),
            Methods::all(),
            new PkiFrameworkCertificateReader(),
            Algorithms::keyEncryption(),
            Algorithms::contentEncryption(),
        );

        // Then
        $this->expectException(LogicException::class);

        // When
        $definition->keepSecret(new FakePasswordHasher());
    }

    /**
     * @param array<string, array<string, mixed>> $clients
     */
    /**
     * Architecture §4.6: what the tenant issues is read from its registrations, a rotation asks.
     *
     * @param array<string, array<string, mixed>> $clients
     */
    #[Test]
    #[DataProvider('provideRegistrationsAndTheFormatsTheyIssue')]
    public function theTenantIssuesTheAccessTokenFormatsItsClientsAreRegisteredFor(array $clients, AccessTokenFormat $format, bool $expected): void
    {
        // Given
        $repository = $this->repository($clients);

        // When / Then
        static::assertSame($expected, $repository->issuesAccessTokensIn($this->tenant, $format));
    }

    /**
     * @return iterable<string, array{array<string, array<string, mixed>>, AccessTokenFormat, bool}>
     */
    public static function provideRegistrationsAndTheFormatsTheyIssue(): iterable
    {
        $opaque = [
            ...self::SPA,
            'access_token_format' => 'opaque',
        ];
        yield 'jwt by default' => [
            [
                'spa' => self::SPA,
            ],
            AccessTokenFormat::Jwt,
            true,
        ];
        yield 'no opaque client' => [
            [
                'spa' => self::SPA,
            ],
            AccessTokenFormat::Opaque,
            false,
        ];
        yield 'one opaque client among jwt ones' => [
            [
                'spa' => self::SPA,
                'api' => $opaque,
            ],
            AccessTokenFormat::Opaque,
            true,
        ];
        yield 'every client opaque, no jwt' => [
            [
                'api' => $opaque,
            ],
            AccessTokenFormat::Jwt,
            false,
        ];
        yield 'no client at all' => [[], AccessTokenFormat::Jwt, false];
    }

    #[Test]
    public function anotherTenantIssuesNothingHere(): void
    {
        // Given
        $repository = $this->repository([
            'spa' => self::SPA,
        ]);

        // When / Then
        static::assertFalse($repository->issuesAccessTokensIn(Fixtures::tenant('other', 'https://id.other.example'), AccessTokenFormat::Jwt));
    }

    /**
     * @param array<string, array<string, mixed>> $clients
     */
    private function repository(array $clients, ?PasswordHasherInterface $hasher = null): ConfigurationClientRepository
    {
        return new ConfigurationClientRepository(
            $this->tenant->slug,
            $clients,
            $hasher ?? new FakePasswordHasher(),
            Algorithms::all(),
            Methods::all(),
            new PkiFrameworkCertificateReader(),
            Algorithms::keyEncryption(),
            Algorithms::contentEncryption(),
        );
    }

    private static function find(ConfigurationClientRepository $repository, Tenant $tenant, string $clientId): Client
    {
        return $repository->findByClientId($tenant, $clientId) ?? static::fail(sprintf('The client "%s" should have been found.', $clientId));
    }

    /**
     * OIDC Registration §2: what the client registered in "request_object_signing_alg" and in
     * "request_uris" is read as it is written, the algorithm among those the provider is wired with.
     */
    #[Test]
    public function aClientRegistersHowItSignsItsRequestObjectsAndWhereTheyArePublished(): void
    {
        // Given
        $repository = $this->repository([
            'jar' => self::KEY_CLIENT
                + [
                    'request_object_signing_alg' => 'ES256',
                    'request_uris' => ['https://key.example/request.jwt'],
                ],
        ]);

        // When
        $client = self::find($repository, $this->tenant, 'jar');

        // Then
        static::assertTrue($client->requestObjectSigning->accepts('ES256', ['RS256', 'PS256', 'ES256', 'EdDSA']));
        static::assertFalse($client->requestObjectSigning->accepts('PS256', ['RS256', 'PS256', 'ES256', 'EdDSA']));
        static::assertSame('https://key.example/request.jwt', $client->registeredRequestUri('https://key.example/request.jwt')?->value);
    }

    /**
     * Decision 0006: "none" is registered per client, and the tenant announces it because a client of
     * its own registered it (issue #98).
     *
     * @param array<string, array<string, mixed>> $clients
     */
    #[Test]
    #[DataProvider('provideRegistrationsAndWhatTheyAnnounce')]
    public function theTenantReadsUnsignedRequestObjectsWhenAClientRegisteredThem(array $clients, bool $expected): void
    {
        // Given
        $repository = $this->repository($clients);

        // When / Then
        static::assertSame($expected, $repository->acceptsUnsignedRequestObjects($this->tenant));
    }

    /**
     * @return iterable<string, array{array<string, array<string, mixed>>, bool}>
     */
    public static function provideRegistrationsAndWhatTheyAnnounce(): iterable
    {
        $unsigned = self::SPA
        + [
            'request_object_signing_alg' => 'none',
        ];
        yield 'no client registers none' => [
            [
                'spa' => self::SPA,
            ],
            false,
        ];
        yield 'one client among others registers none' => [
            [
                'spa' => self::SPA,
                'unsigned' => $unsigned,
            ],
            true,
        ];
        yield 'no client at all' => [[], false];
    }

    #[Test]
    public function anotherTenantReadsNoUnsignedRequestObjectHere(): void
    {
        // Given
        $repository = $this->repository([
            'unsigned' => self::SPA
                + [
                    'request_object_signing_alg' => 'none',
                ],
        ]);

        // When / Then
        static::assertFalse($repository->acceptsUnsignedRequestObjects(Fixtures::tenant('other', 'https://id.other.example')));
    }
}
