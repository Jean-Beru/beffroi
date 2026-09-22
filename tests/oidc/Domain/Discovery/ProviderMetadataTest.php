<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Discovery;

use function array_keys;
use function array_map;
use function array_slice;
use Heidi\Core\Domain\Key\ContentEncryptionAlgorithmInterface;
use Heidi\Core\Domain\Key\KeyEncryptionAlgorithmInterface;
use Heidi\Core\Domain\Key\SignatureAlgorithmInterface;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Oidc\Domain\Authorization\ResponseMode;
use Heidi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Heidi\Oidc\Domain\Client\GrantType;
use Heidi\Oidc\Domain\Discovery\ProviderEndpoints;
use Heidi\Oidc\Domain\Discovery\ProviderMetadata;
use Heidi\Oidc\Domain\EndSession\LogoutChannel;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\LogoutChannels;
use Heidi\Oidc\Tests\Fixture\Methods;
use function json_decode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class ProviderMetadataTest extends TestCase
{
    /**
     * OIDC Discovery §3: the members, in the order the section lists them, then those of RFC 8414 §2
     * ("code_challenge_methods_supported", the revocation and introspection endpoints with their
     * authentication methods, RFC 7009 §2.1 and RFC 7662 §2.1, and the algorithms of a signed introspection
     * response, RFC 9701 §6), "authorization_response_iss_parameter_supported" (RFC 9207 §3) and
     * "end_session_endpoint" (RP-Initiated Logout §2.1) and the four members of the two logout
     * specifications (Back-Channel Logout 1.0 §3, Front-Channel Logout 1.0 §3) and what RFC 8705 §3.3 asks
     * of a provider that binds an access token to a certificate, said as "no" by a provider that does
     * not. Only what the provider
     * does: "code", "query",
     * "S256", "public", "RS256", the client authentication methods it is wired with at the token and
     * revocation endpoints, those of them that authenticate the caller at introspection, what an
     * assertion of those methods may be signed with, the "acr" values given, no request object.
     */
    #[Test]
    public function itDescribesWhatTheProviderDoesAndNothingElse(): void
    {
        // When
        $document = self::metadata()->toArray();

        // Then
        static::assertSame([
            'issuer' => 'https://id.acme.example',
            'authorization_endpoint' => 'https://id.acme.example/authorize',
            'token_endpoint' => 'https://id.acme.example/token',
            'userinfo_endpoint' => 'https://id.acme.example/userinfo',
            'jwks_uri' => 'https://id.acme.example/jwks',
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access'],
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query', 'form_post'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'acr_values_supported' => ['phrh', 'phr', '2', '1'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
            'id_token_encryption_alg_values_supported' => ['ECDH-ES+A256KW', 'RSA-OAEP-256'],
            'id_token_encryption_enc_values_supported' => ['A256GCM'],
            'userinfo_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
            'userinfo_encryption_alg_values_supported' => ['ECDH-ES+A256KW', 'RSA-OAEP-256'],
            'userinfo_encryption_enc_values_supported' => ['A256GCM'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'client_secret_jwt', 'none'],
            'token_endpoint_auth_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA', 'HS256'],
            'claims_supported' => ['sub', 'name', 'email', 'email_verified'],
            'claims_parameter_supported' => true,
            'request_parameter_supported' => true,
            'request_uri_parameter_supported' => true,
            'require_request_uri_registration' => true,
            'request_object_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
            'request_object_encryption_alg_values_supported' => ['ECDH-ES+A256KW', 'RSA-OAEP-256'],
            'request_object_encryption_enc_values_supported' => ['A256GCM'],
            'code_challenge_methods_supported' => ['S256'],
            'revocation_endpoint' => 'https://id.acme.example/revoke',
            'revocation_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'client_secret_jwt', 'none'],
            'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA', 'HS256'],
            'pushed_authorization_request_endpoint' => 'https://id.acme.example/par',
            'require_pushed_authorization_requests' => false,
            'introspection_endpoint' => 'https://id.acme.example/introspect',
            'introspection_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'client_secret_jwt'],
            'introspection_endpoint_auth_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA', 'HS256'],
            'introspection_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
            'authorization_response_iss_parameter_supported' => true,
            'end_session_endpoint' => 'https://id.acme.example/logout',
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
            'frontchannel_logout_supported' => true,
            'frontchannel_logout_session_supported' => true,
            'tls_client_certificate_bound_access_tokens' => false,
            'dpop_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
        ], $document);
    }

    /**
     * OIDC Discovery §3 and issue #164: what a client may encrypt a request object with is what the
     * wiring gave the provider, the key management algorithms and the content encryption ones.
     */
    #[Test]
    public function itAnnouncesWhatARequestObjectMayBeEncryptedToItWith(): void
    {
        // When
        $document = self::metadata()->toArray();

        // Then
        static::assertSame(['ECDH-ES+A256KW', 'RSA-OAEP-256'], $document['request_object_encryption_alg_values_supported']);
        static::assertSame(['A256GCM'], $document['request_object_encryption_enc_values_supported']);
    }

    /**
     * Issue #165: the same wired lists answer for every kind of document at once, because the provider
     * opens and mints them all with them. A deployment that wires encryption announces it for the request
     * object a client encrypts to it and for the three documents it encrypts to a client.
     */
    #[Test]
    public function itAnnouncesTheSameEncryptionForEveryKindOfDocument(): void
    {
        // When
        $document = self::metadata()->toArray();

        // Then
        foreach (['id_token_encryption', 'userinfo_encryption', 'request_object_encryption'] as $member) {
            static::assertSame(['ECDH-ES+A256KW', 'RSA-OAEP-256'], $document[$member . '_alg_values_supported'], $member);
            static::assertSame(['A256GCM'], $document[$member . '_enc_values_supported'], $member);
        }
    }

    /**
     * OIDC Core §5.3.2 and OIDC Discovery §3: a client may have the UserInfo answer signed by the tenant,
     * with the algorithms the provider signs everything else with.
     */
    #[Test]
    public function itAnnouncesWhatAUserInfoAnswerMayBeSignedWith(): void
    {
        // When
        $document = self::metadata()->toArray();

        // Then
        static::assertSame(['RS256', 'PS256', 'ES256', 'EdDSA'], $document['userinfo_signing_alg_values_supported']);
    }

    /**
     * JARM §3: the two members that say what a signed authorization response may be encrypted with are
     * announced where a signed mode is wired, and nowhere else: a deployment that signs no answer has
     * none to encrypt.
     */
    #[Test]
    public function itAnnouncesWhatASignedAuthorizationResponseMayBeEncryptedWithWhereOneIsWired(): void
    {
        // Given
        $signed = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], [ResponseMode::Query, ResponseMode::QueryJwt], self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), self::keyEncryptionAlgorithms(), self::contentEncryptionAlgorithms(), 60)->toArray();

        // Then
        static::assertSame(['ECDH-ES+A256KW', 'RSA-OAEP-256'], $signed['authorization_encryption_alg_values_supported']);
        static::assertSame(['A256GCM'], $signed['authorization_encryption_enc_values_supported']);
        static::assertArrayNotHasKey('authorization_encryption_alg_values_supported', self::metadata()->toArray());
    }

    /**
     * An algorithm wired twice is announced once, as every other list of the document is.
     */
    #[Test]
    public function anEncryptionAlgorithmWiredTwiceIsAnnouncedOnce(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [Algorithms::ecdhEsA256Kw(), Algorithms::rsaOaep256(), Algorithms::ecdhEsA256Kw()], [Algorithms::a256Gcm(), Algorithms::a256Gcm()], 60)->toArray();

        // Then
        static::assertSame(['ECDH-ES+A256KW', 'RSA-OAEP-256'], $document['request_object_encryption_alg_values_supported']);
        static::assertSame(['A256GCM'], $document['request_object_encryption_enc_values_supported']);
    }

    /**
     * A deployment nobody encrypts to wires neither an "alg" nor an "enc", and announces neither rather
     * than two empty lists a client would read as a promise.
     *
     * @param list<KeyEncryptionAlgorithmInterface> $keyEncryption
     * @param list<ContentEncryptionAlgorithmInterface> $contentEncryption
     */
    #[Test]
    #[DataProvider('provideIncompleteEncryptionWirings')]
    public function aProviderNobodyEncryptsToAnnouncesNeitherList(array $keyEncryption, array $contentEncryption): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), $keyEncryption, $contentEncryption, 60)->toArray();

        // Then
        static::assertArrayNotHasKey('request_object_encryption_alg_values_supported', $document);
        static::assertArrayNotHasKey('request_object_encryption_enc_values_supported', $document);
    }

    /**
     * @return iterable<string, array{list<KeyEncryptionAlgorithmInterface>, list<ContentEncryptionAlgorithmInterface>}>
     */
    public static function provideIncompleteEncryptionWirings(): iterable
    {
        yield 'nothing wired' => [[], []];
        yield 'an alg that would open nothing' => [Algorithms::keyEncryption()->all(), []];
        yield 'an enc nothing unwraps a key for' => [[], Algorithms::contentEncryption()->all()];
    }

    #[Test]
    public function itIsPubliclyCacheableForItsLifetime(): void
    {
        // When
        $metadata = self::metadata();

        // Then
        static::assertSame([
            'Cache-Control' => 'public, max-age=3600',
        ], $metadata->headers);
    }

    /**
     * The JSON a client reads: booleans as JSON booleans (oidc_login compares
     * "authorization_response_iss_parameter_supported" to true with ===), lists as JSON arrays, the
     * issuer byte for byte (OIDC Discovery §4.3).
     */
    #[Test]
    public function theJsonCarriesBooleansAndListsAsTheyAre(): void
    {
        // When
        $json = self::metadata()->toJson();

        // Then
        static::assertStringContainsString('"issuer":"https://id.acme.example",', $json);
        static::assertStringContainsString('"claims_parameter_supported":true,"request_parameter_supported":true,"request_uri_parameter_supported":true,"require_request_uri_registration":true,', $json);
        static::assertStringContainsString('"authorization_response_iss_parameter_supported":true,', $json);
        static::assertStringContainsString('"response_types_supported":["code"],', $json);
    }

    #[Test]
    public function theJsonIsTheDocument(): void
    {
        // When
        $decoded = json_decode(self::metadata()->toJson(), true, 4, JSON_THROW_ON_ERROR);

        // Then
        static::assertSame(self::metadata()->toArray(), $decoded);
        static::assertTrue($decoded['authorization_response_iss_parameter_supported']);
    }

    /**
     * OIDC Discovery §3: "openid" MUST be supported and "sub" is always a claim; both come first whatever
     * the integration lists, and a scope or a claim listed twice is announced once.
     */
    #[Test]
    public function openidAndSubComeFirstAndOnce(): void
    {
        // When
        $metadata = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [new Scope('email'), new Scope('openid'), new Scope('email')], ['email', 'sub', 'email'], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60);

        // Then
        static::assertSame(['openid', 'email'], array_map(static fn (Scope $scope): string => $scope->value, $metadata->scopesSupported));
        static::assertSame(['sub', 'email'], $metadata->claimsSupported);
    }

    #[Test]
    public function openidAndSubAreAnnouncedEvenWhenTheIntegrationListsNothing(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60)->toArray();

        // Then
        static::assertSame(['openid'], $document['scopes_supported']);
        static::assertSame(['sub'], $document['claims_supported']);
    }

    /**
     * OIDC Discovery §4.1 appends the well-known path to the issuer; RFC 8414 §3 inserts it between the
     * host and the path of the issuer. Both are the same location when the issuer has no path.
     */
    #[Test]
    public function theWellKnownLocationsOfAnIssuerWithoutPathCoincide(): void
    {
        // When
        $metadata = self::metadata();

        // Then
        static::assertSame('https://id.acme.example/.well-known/openid-configuration', $metadata->openIdConfigurationUrl());
        static::assertSame('https://id.acme.example/.well-known/oauth-authorization-server', $metadata->authorizationServerMetadataUrl());
    }

    #[Test]
    public function theWellKnownLocationsOfAnIssuerWithAPathDiffer(): void
    {
        // When
        $metadata = new ProviderMetadata(new Issuer('https://as.example:8443/tenants/acme'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60);

        // Then
        static::assertSame('https://as.example:8443/tenants/acme/.well-known/openid-configuration', $metadata->openIdConfigurationUrl());
        static::assertSame('https://as.example:8443/.well-known/oauth-authorization-server/tenants/acme', $metadata->authorizationServerMetadataUrl());
        static::assertSame('https://as.example:8443/tenants/acme', $metadata->toArray()['issuer']);
    }

    /**
     * The cache lifetime is a number of seconds, zero meaning "revalidate every time".
     */
    #[Test]
    public function aLifetimeOfZeroRevalidatesEveryTime(): void
    {
        // When
        $metadata = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 0);

        // Then
        static::assertSame([
            'Cache-Control' => 'public, max-age=0',
        ], $metadata->headers);
    }

    #[Test]
    public function aNegativeLifetimeIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('number of seconds');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], -1);
    }

    /**
     * RFC 8414 §2: the lists say what is wired, a grant, a method or a class listed twice counts once, nothing wired is a fault.
     */
    #[Test]
    public function theGrantTypesAndTheMethodsAreThoseGivenEachOnce(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), [GrantType::AuthorizationCode, GrantType::AuthorizationCode], [Methods::none(), Methods::none()], ['1', '1'], self::algorithms(), self::channels(), [], [], 60)->toArray();

        // Then
        static::assertSame(['authorization_code'], $document['grant_types_supported']);
        static::assertSame(['none'], $document['token_endpoint_auth_methods_supported']);
        static::assertSame(['none'], $document['revocation_endpoint_auth_methods_supported']);
        static::assertSame(['1'], $document['acr_values_supported']);
    }

    /**
     * RFC 8414 §2: the response modes are those given, a mode wired twice counted once.
     */
    #[Test]
    public function theResponseModesAreThoseGivenEachOnce(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], [ResponseMode::FormPost, ResponseMode::Query, ResponseMode::FormPost], self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60)->toArray();

        // Then
        static::assertSame(['form_post', 'query'], $document['response_modes_supported']);
    }

    /**
     * JARM §2.1 and issue #98: "jwt" is announced because a signed mode is wired, and with it what such
     * an answer is signed with (JARM §3); the alias comes last, after the modes that deliver.
     */
    #[Test]
    public function aWiredSignedModeAnnouncesTheAliasAndWhatSignsIt(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], [ResponseMode::Query, ResponseMode::QueryJwt], self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60)->toArray();

        // Then
        static::assertSame(['query', 'query.jwt', 'jwt'], $document['response_modes_supported']);
        static::assertSame($document['id_token_signing_alg_values_supported'], $document['authorization_signing_alg_values_supported']);
    }

    /**
     * A deployment that answers in "query" and "form_post" alone signs no answer, so it announces
     * neither the alias nor what would sign one.
     */
    #[Test]
    public function aDeploymentWithoutASignedModeAnnouncesNeitherTheAliasNorWhatSignsIt(): void
    {
        // When
        $document = self::metadata()->toArray();

        // Then
        static::assertSame(['query', 'form_post'], $document['response_modes_supported']);
        static::assertArrayNotHasKey('authorization_signing_alg_values_supported', $document);
    }

    /**
     * OIDC Registration §2 and decision 0006: "none" is announced beside the algorithms when a client of
     * the tenant registered it, and a deployment whose clients all sign their request objects does not
     * announce that it would read an unsigned one (issue #98).
     *
     * @param list<string> $expected
     */
    #[Test]
    #[DataProvider('provideWhatTheClientsRegistered')]
    public function theRequestObjectAlgorithmsAnnouncedAreTheWiredOnesAndWhatAClientRegistered(bool $unsigned, array $expected): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, $unsigned, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60)->toArray();

        // Then
        static::assertSame($expected, $document['request_object_signing_alg_values_supported']);
    }

    /**
     * @return iterable<string, array{bool, list<string>}>
     */
    public static function provideWhatTheClientsRegistered(): iterable
    {
        yield 'every client signs its objects' => [false, ['RS256', 'PS256', 'ES256', 'EdDSA']];
        yield 'one client registered none' => [true, ['RS256', 'PS256', 'ES256', 'EdDSA', 'none']];
    }

    /**
     * OIDC Discovery §3: a provider that could assert no class would announce nothing; decision 0010 makes
     * every policy name the single factor, so the list is never empty.
     */
    #[Test]
    public function noAcrValueIsAFault(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider asserts at least one authentication context class (OIDC Discovery section 3).');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), [], self::algorithms(), self::channels(), [], [], 60);
    }

    /**
     * RFC 7662 §2.1: introspection takes the methods that authenticate the caller, among those the
     * provider takes; a public client has none.
     */
    #[Test]
    public function introspectionTakesTheAuthenticatingMethodsAmongThoseGiven(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), [GrantType::AuthorizationCode], [Methods::clientSecretPost(), Methods::none()], ['1'], self::algorithms(), self::channels(), [], [], 60)->toArray();

        // Then
        static::assertSame(['client_secret_post'], $document['introspection_endpoint_auth_methods_supported']);
    }

    #[Test]
    public function noResponseModeIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An authorization endpoint answers in at least one response mode (RFC 8414 section 2).');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], [], self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60);
    }

    #[Test]
    public function noGrantTypeIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A provider serves at least one grant type (RFC 8414 section 2).');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), [], self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60);
    }

    #[Test]
    public function noAuthenticationMethodIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A token endpoint takes at least one client authentication method (RFC 8414 section 2).');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), [], ['1'], self::algorithms(), self::channels(), [], [], 60);
    }

    #[Test]
    public function anEmptyClaimNameIsRefused(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('A supported claim has a name.');

        // When
        new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [''], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60);
    }

    /**
     * What Symfony's OidcDiscovery checks before it uses a document: the "issuer" equals the configured
     * one, and every endpoint it reads is over HTTPS, the token endpoint even on loopback. The document
     * of a loopback issuer in development passes those checks too.
     */
    #[Test]
    #[DataProvider('provideIssuers')]
    public function itPassesTheChecksOfSymfonyOidcDiscovery(string $issuer): void
    {
        // When
        $document = new ProviderMetadata(new Issuer($issuer), new ProviderEndpoints($issuer . '/authorize', $issuer . '/token', $issuer . '/userinfo', $issuer . '/jwks', $issuer . '/logout', $issuer . '/introspect', $issuer . '/revoke', $issuer . '/par'), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), self::channels(), [], [], 60)->toArray();

        // Then
        static::assertSame($issuer, $document['issuer']);
        foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'end_session_endpoint', 'introspection_endpoint', 'revocation_endpoint'] as $endpoint) {
            static::assertIsString($document[$endpoint]);
            static::assertStringStartsWith('https://', $document[$endpoint]);
        }
        static::assertTrue($document['authorization_response_iss_parameter_supported']);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideIssuers(): iterable
    {
        yield 'public host' => ['https://id.acme.example'];
        yield 'loopback host' => ['https://op.localhost'];
    }

    #[Test]
    public function theIssuerAndTheEndpointsComeFirst(): void
    {
        // When
        $members = array_keys(self::metadata()->toArray());

        // Then
        static::assertSame(['issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'], array_slice($members, 0, 5));
    }

    /**
     * A channel two things serve is announced once, and the list stays a list.
     */
    /**
     * RFC 8414 §2: an algorithm the wiring gives twice is announced once, as every other list of the
     * document.
     */
    #[Test]
    public function anAlgorithmWiredTwiceIsAnnouncedOnce(): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], [Algorithms::rs256(), Algorithms::es256(), Algorithms::rs256()], self::channels(), [], [], 60)->toArray();

        // Then
        static::assertSame(['RS256', 'ES256'], $document['id_token_signing_alg_values_supported']);
    }

    #[Test]
    public function aChannelWiredTwiceIsAnnouncedOnce(): void
    {
        // When
        $metadata = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), [LogoutChannel::BackChannel, LogoutChannel::BackChannel, LogoutChannel::FrontChannel], [], [], 60);

        // Then
        static::assertSame([LogoutChannel::BackChannel, LogoutChannel::FrontChannel], $metadata->logoutChannelsSupported);
    }

    /**
     * Back-Channel Logout 1.0 §3, Front-Channel Logout 1.0 §3: the document announces a channel only
     * where something serves it, and a channel that is served always carries the session.
     */
    #[Test]
    #[DataProvider('provideServedChannels')]
    public function theLogoutChannelsAnnouncedAreTheOnesServed(LogoutChannels $served, bool $backChannel, bool $frontChannel): void
    {
        // When
        $document = new ProviderMetadata(new Issuer('https://id.acme.example'), self::endpoints(), null, false, false, [], [], self::responseModes(), self::grantTypes(), self::methods(), ['1'], self::algorithms(), $served->channels, [], [], 60)->toArray();

        // Then
        static::assertSame($backChannel, $document['backchannel_logout_supported']);
        static::assertSame($backChannel, $document['backchannel_logout_session_supported']);
        static::assertSame($frontChannel, $document['frontchannel_logout_supported']);
        static::assertSame($frontChannel, $document['frontchannel_logout_session_supported']);
    }

    /**
     * @return iterable<string, array{LogoutChannels, bool, bool}>
     */
    public static function provideServedChannels(): iterable
    {
        yield 'both wired' => [new LogoutChannels([LogoutChannel::BackChannel, LogoutChannel::FrontChannel]), true, true];
        yield 'the back channel alone' => [new LogoutChannels([LogoutChannel::BackChannel]), true, false];
        yield 'the front channel alone' => [new LogoutChannels([LogoutChannel::FrontChannel]), false, true];
        yield 'a deployment that tells nobody' => [new LogoutChannels([]), false, false];
    }

    private static function metadata(): ProviderMetadata
    {
        return new ProviderMetadata(
            new Issuer('https://id.acme.example'),
            self::endpoints(),
            null,
            false,
            false,
            [new Scope('openid'), new Scope('profile'), new Scope('email'), new Scope('offline_access')],
            ['name', 'email', 'email_verified'],
            self::responseModes(),
            self::grantTypes(),
            self::methods(),
            ['phrh', 'phr', '2', '1'],
            self::algorithms(),
            self::channels(),
            self::keyEncryptionAlgorithms(),
            self::contentEncryptionAlgorithms(),
            3600,
        );
    }

    /**
     * @return non-empty-list<SignatureAlgorithmInterface>
     */
    private static function algorithms(): array
    {
        return Algorithms::all()->all();
    }

    /**
     * @return list<KeyEncryptionAlgorithmInterface>
     */
    private static function keyEncryptionAlgorithms(): array
    {
        return Algorithms::keyEncryption()->all();
    }

    /**
     * @return list<ContentEncryptionAlgorithmInterface>
     */
    private static function contentEncryptionAlgorithms(): array
    {
        return Algorithms::contentEncryption()->all();
    }

    /**
     * @return list<LogoutChannel>
     */
    private static function channels(): array
    {
        return [LogoutChannel::BackChannel, LogoutChannel::FrontChannel];
    }

    /**
     * @return list<ResponseMode>
     */
    private static function responseModes(): array
    {
        return [ResponseMode::Query, ResponseMode::FormPost];
    }

    /**
     * @return list<GrantType>
     */
    private static function grantTypes(): array
    {
        return [GrantType::AuthorizationCode, GrantType::RefreshToken];
    }

    /**
     * @return list<ClientAuthenticationMethodInterface>
     */
    private static function methods(): array
    {
        return [Methods::clientSecretBasic(), Methods::clientSecretPost(), Methods::privateKeyJwt(), Methods::clientSecretJwt(), Methods::none()];
    }

    private static function endpoints(): ProviderEndpoints
    {
        return new ProviderEndpoints('https://id.acme.example/authorize', 'https://id.acme.example/token', 'https://id.acme.example/userinfo', 'https://id.acme.example/jwks', 'https://id.acme.example/logout', 'https://id.acme.example/introspect', 'https://id.acme.example/revoke', 'https://id.acme.example/par');
    }
}
