<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use function array_map;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\Certificate\SubjectDistinguishedName;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Domain\Client\ClientJwks;
use Heidi\Oidc\Domain\Client\ClientUri;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\ClientAssertions;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Methods;
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
        static::assertInstanceOf(HashedClientSecret::class, $client->secret);
        static::assertSame($hash, $client->secret->hash);
        static::assertSame('client_secret_basic', $client->authenticationMethod->name());
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
     * Decision 0008: PKCE is the rule.
     */
    #[Test]
    public function aClientRequiresPkceUnlessRegisteredOtherwise(): void
    {
        // When
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // Then
        static::assertTrue($client->requiresPkce);
    }

    /**
     * Decision 0008: the named exception is carried by a confidential client.
     */
    #[Test]
    public function aConfidentialClientMayBeRegisteredWithoutThePkceRequirement(): void
    {
        // When
        $client = Clients::confidential(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET), requiresPkce: false);

        // Then
        static::assertFalse($client->requiresPkce);
    }

    /**
     * RFC 9700 §2.1.1: a public client MUST use PKCE; the exception of decision 0008 is not for it.
     */
    #[Test]
    public function aPublicClientCannotBeRegisteredWithoutThePkceRequirement(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "spa" is public and must use PKCE (RFC 9700 section 2.1.1): requires_pkce cannot be false.');

        // When
        new Client(Fixtures::tenant(), 'spa', 'Single page application', Methods::none(), null, [new RedirectUri('https://spa.example/callback')], requiresPkce: false);
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
        static::assertNull($client->secret);
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
            Methods::none(),
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
        $this->expectExceptionMessageIsOrContains($reason);

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
            static fn (Tenant $tenant): Client => new Client($tenant, '', 'Name', Methods::none(), null, $uris),
            'visible ASCII',
        ];
        yield 'client id with a trailing space' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo ', 'Name', Methods::none(), null, $uris),
            'visible ASCII',
        ];
        yield 'client id with a control character' => [
            static fn (Tenant $tenant): Client => new Client($tenant, "de\tmo", 'Name', Methods::none(), null, $uris),
            'visible ASCII',
        ];
        yield 'client id beyond ASCII (RFC 6749 appendix A.1)' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'démo', 'Name', Methods::none(), null, $uris),
            'visible ASCII',
        ];
        yield 'empty name' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', '', Methods::none(), null, $uris),
            'has a name',
        ];
        yield 'client_secret_basic without a secret' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', Methods::clientSecretBasic(), null, $uris),
            'needs a secret',
        ];
        yield 'client_secret_post without a secret' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', Methods::clientSecretPost(), null, $uris),
            'needs a secret',
        ];
        yield 'none with a secret (RFC 6749 §2.1)' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', Methods::none(), new HashedClientSecret($hash), $uris),
            'cannot hold a secret',
        ];
        yield 'no redirect URI (RFC 6749 §3.1.2.2)' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', Methods::none(), null, []),
            'at least one redirect URI',
        ];
        yield 'no grant type' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', Methods::none(), null, $uris, [], []),
            'at least one grant type',
        ];
        yield 'refresh_token alone' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', Methods::none(), null, $uris, [], [GrantType::RefreshToken]),
            'requires authorization_code',
        ];
        yield 'no scope' => [
            static fn (Tenant $tenant): Client => new Client($tenant, 'demo', 'Name', Methods::none(), null, $uris, [], [GrantType::AuthorizationCode], []),
            'at least one scope',
        ];
    }

    /**
     * RFC 6749 §2.1: "none" is the method of a public client and the only one that authenticates nothing.
     */
    #[Test]
    #[DataProvider('provideAuthenticationMethods')]
    public function aMethodSaysWhetherItAuthenticatesTheClient(ClientAuthenticationMethodInterface $method, bool $authenticates): void
    {
        // When / Then
        static::assertSame($authenticates, $method->authenticatesClient());
    }

    /**
     * @return iterable<string, array{ClientAuthenticationMethodInterface, bool}>
     */
    public static function provideAuthenticationMethods(): iterable
    {
        yield 'client_secret_basic' => [Methods::clientSecretBasic(), true];
        yield 'client_secret_post' => [Methods::clientSecretPost(), true];
        yield 'private_key_jwt' => [Methods::privateKeyJwt(), true];
        yield 'client_secret_jwt' => [Methods::clientSecretJwt(), true];
        yield 'none' => [Methods::none(), false];
    }

    /**
     * OIDC Core §9: a method that verifies a signature of the client needs the keys of the client, and a
     * registration that publishes none cannot work.
     */
    #[Test]
    public function aClientThatSignsItsAssertionsPublishesItsKeys(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('publishes its keys in "jwks" or behind a "jwks_uri"');

        // When
        new Client(Fixtures::tenant(), 'key-client', 'Key client', Methods::privateKeyJwt(), null, [new RedirectUri('https://key.example/callback')]);
    }

    /**
     * RFC 7591 §2: "jwks" and "jwks_uri" are exclusive.
     */
    #[Test]
    public function aClientPublishesItsKeysOneWayOrTheOther(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('either inline in "jwks" or behind a "jwks_uri", never both');

        // When
        new Client(Fixtures::tenant(), 'key-client', 'Key client', Methods::privateKeyJwt(), null, [new RedirectUri('https://key.example/callback')], jwks: ClientAssertions::publishedKeys(), jwksUri: new ClientUri('https://key.example/jwks'));
    }

    /**
     * RFC 8705 §2.1: a method that recognises a client by what its certificate says about it needs the
     * registration to say what that is, and a registration that says nothing cannot work.
     */
    #[Test]
    public function aClientRecognisedByItsCertificateRegistersWhatNamesItInIt(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers one of the values of RFC 8705 section 2.1.2');

        // When
        new Client(Fixtures::tenant(), 'mtls-client', 'Mutual TLS client', Methods::tlsClientAuth(), null, [new RedirectUri('https://mtls.example/callback')]);
    }

    /**
     * The other way round: a method that reads nothing of a certificate is registered with nothing about
     * one, so that a registration never carries a rule nobody applies.
     */
    #[Test]
    public function aClientAuthenticatedOtherwiseRegistersNothingOfACertificate(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers none of the values of RFC 8705 section 2.1.2');

        // When
        new Client(Fixtures::tenant(), 'spa', 'Single page application', Methods::none(), null, [new RedirectUri('https://spa.example/callback')], certificateIdentity: new SubjectDistinguishedName('cn=client'));
    }

    /**
     * RFC 8705 §2.2: the self-signed method reads the keys of the client, as "private_key_jwt" does, and
     * a registration that publishes none cannot work either.
     */
    #[Test]
    public function aClientAuthenticatedByASelfSignedCertificatePublishesIt(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('publishes its keys in "jwks" or behind a "jwks_uri"');

        // When
        new Client(Fixtures::tenant(), 'self-signed-client', 'Self-signed client', Methods::selfSignedTlsClientAuth(), null, [new RedirectUri('https://self-signed.example/callback')]);
    }

    /**
     * OIDC Core §9: "client_secret_basic" is shown the secret and keeps a hash of it;
     * "client_secret_jwt" computes a MAC with it and keeps the secret. A secret kept for one is not a
     * secret the other verifies against.
     */
    #[Test]
    public function aSecretIsKeptInTheShapeTheRegisteredMethodVerifiesAgainst(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not kept in a shape client_secret_basic verifies against');

        // When
        new Client(Fixtures::tenant(), 'demo', 'Name', Methods::clientSecretBasic(), new SharedClientSecret(Clients::SECRET), [new RedirectUri('https://rp.example/cb')]);
    }

    /**
     * A client that publishes keys without registering a method that uses them is not refused: RFC 7591
     * §2 lets a client publish keys for more than one purpose.
     */
    #[Test]
    public function aClientMayPublishKeysWithoutAuthenticatingWithThem(): void
    {
        // When
        $client = new Client(Fixtures::tenant(), 'spa', 'Single page application', Methods::none(), null, [new RedirectUri('https://spa.example/callback')], jwks: ClientAssertions::publishedKeys());

        // Then
        static::assertInstanceOf(ClientJwks::class, $client->jwks);
    }
}
