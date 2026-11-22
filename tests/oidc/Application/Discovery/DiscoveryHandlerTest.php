<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery;

use function array_keys;
use function array_slice;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\DiscoveryHandler;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Port\MetadataContributorInterface;
use Beffroi\Oidc\Tests\Fixture\ProviderDocument;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class DiscoveryHandlerTest extends TestCase
{
    /**
     * OIDC Discovery §3, RFC 8414 §2, RFC 7009 §2.1, RFC 7662 §2.1, RFC 9701 §6, RFC 9207 §3,
     * RP-Initiated Logout §2.1, Back-Channel Logout 1.0 §3, Front-Channel Logout 1.0 §3, RFC 8705 §3.3
     */
    #[Test]
    public function itDescribesWhatTheProviderDoesAndNothingElse(): void
    {
        // When
        $document = ProviderDocument::of();

        // Then
        static::assertSame(
            [
                'issuer' => 'https://id.acme.example',
                'authorization_endpoint' => 'https://id.acme.example/authorize',
                'token_endpoint' => 'https://id.acme.example/token',
                'userinfo_endpoint' => 'https://id.acme.example/userinfo',
                'jwks_uri' => 'https://id.acme.example/jwks',
                'scopes_supported' => ['openid', 'profile', 'email', 'address', 'phone', 'offline_access'],
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
                'token_endpoint_auth_methods_supported' => [
                    'client_secret_basic',
                    'client_secret_post',
                    'private_key_jwt',
                    'client_secret_jwt',
                    'tls_client_auth',
                    'self_signed_tls_client_auth',
                    'none',
                ],
                'token_endpoint_auth_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA', 'HS256'],
                'claims_supported' => [
                    'sub',
                    'name',
                    'family_name',
                    'given_name',
                    'middle_name',
                    'nickname',
                    'preferred_username',
                    'profile',
                    'picture',
                    'website',
                    'gender',
                    'birthdate',
                    'zoneinfo',
                    'locale',
                    'updated_at',
                    'email',
                    'email_verified',
                    'address',
                    'phone_number',
                    'phone_number_verified',
                ],
                'claims_parameter_supported' => true,
                'request_parameter_supported' => true,
                'request_uri_parameter_supported' => true,
                'require_request_uri_registration' => true,
                'request_object_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
                'request_object_encryption_alg_values_supported' => ['ECDH-ES+A256KW', 'RSA-OAEP-256'],
                'request_object_encryption_enc_values_supported' => ['A256GCM'],
                'code_challenge_methods_supported' => ['S256'],
                'revocation_endpoint' => 'https://id.acme.example/revoke',
                'revocation_endpoint_auth_methods_supported' => [
                    'client_secret_basic',
                    'client_secret_post',
                    'private_key_jwt',
                    'client_secret_jwt',
                    'tls_client_auth',
                    'self_signed_tls_client_auth',
                    'none',
                ],
                'revocation_endpoint_auth_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA', 'HS256'],
                'pushed_authorization_request_endpoint' => 'https://id.acme.example/par',
                'require_pushed_authorization_requests' => false,
                'introspection_endpoint' => 'https://id.acme.example/introspect',
                'introspection_endpoint_auth_methods_supported' => [
                    'client_secret_basic',
                    'client_secret_post',
                    'private_key_jwt',
                    'client_secret_jwt',
                    'tls_client_auth',
                    'self_signed_tls_client_auth',
                ],
                'introspection_endpoint_auth_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA', 'HS256'],
                'introspection_signing_alg_values_supported' => ['RS256'],
                'authorization_response_iss_parameter_supported' => true,
                'end_session_endpoint' => 'https://id.acme.example/logout',
                'backchannel_logout_supported' => true,
                'backchannel_logout_session_supported' => true,
                'frontchannel_logout_supported' => true,
                'frontchannel_logout_session_supported' => true,
                'tls_client_certificate_bound_access_tokens' => true,
                'dpop_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
            ],
            $document,
        );
    }

    /**
     * OIDC Discovery §3
     */
    #[Test]
    public function theIssuerAndTheEndpointsComeFirst(): void
    {
        // When
        $members = array_keys(ProviderDocument::of());

        // Then
        static::assertSame(['issuer', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'], array_slice($members, 0, 5));
    }

    #[Test]
    public function twoCapabilitiesAnnouncingTheSameMemberAreRefused(): void
    {
        // Given
        $handler = new DiscoveryHandler([
            self::contributor([
                'code_challenge_methods_supported' => ['S256'],
            ]),
            self::contributor([
                'code_challenge_methods_supported' => ['plain'],
            ]),
        ]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('Two capabilities of this provider both announce "code_challenge_methods_supported".');

        // When
        $handler->handle(Fixtures::tenant());
    }

    #[Test]
    public function aCapabilityTheDeploymentDoesNotServeAddsNothing(): void
    {
        // Given
        $handler = new DiscoveryHandler([
            self::contributor([
                'authorization_response_iss_parameter_supported' => true,
            ]),
            self::contributor([]),
        ]);

        // When
        $document = $handler->handle(Fixtures::tenant())->toArray();

        // Then
        static::assertSame(
            [
                'authorization_response_iss_parameter_supported' => true,
            ],
            $document,
        );
    }

    /**
     * OIDC Discovery §3
     */
    #[Test]
    public function eachTenantGetsItsOwnIssuerAndEndpoints(): void
    {
        // Given
        $handler = ProviderDocument::handler();

        // When
        $acme = $handler->handle(Fixtures::tenant('acme', 'https://id.acme.example'))->toArray();
        $globex = $handler->handle(Fixtures::tenant('globex', 'https://id.globex.example'))->toArray();

        // Then
        static::assertSame('https://id.acme.example', $acme['issuer']);
        static::assertSame('https://id.acme.example/token', $acme['token_endpoint']);
        static::assertSame('https://id.globex.example', $globex['issuer']);
        static::assertSame('https://id.globex.example/token', $globex['token_endpoint']);
    }

    #[Test]
    public function theDocumentsOfTwoTenantsDifferByTheirLocationsOnly(): void
    {
        // Given
        $handler = ProviderDocument::handler();
        $locations = [
            'issuer',
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'jwks_uri',
            'end_session_endpoint',
            'introspection_endpoint',
            'revocation_endpoint',
            'pushed_authorization_request_endpoint',
        ];

        // When
        $acme = $handler->handle(Fixtures::tenant('acme', 'https://id.acme.example'))->toArray();
        $globex = $handler->handle(Fixtures::tenant('globex', 'https://id.globex.example'))->toArray();

        // Then
        foreach ($locations as $location) {
            unset($acme[$location], $globex[$location]);
        }
        static::assertSame($acme, $globex);
    }

    /**
     * RFC 8414 §3
     */
    #[Test]
    public function theDocumentKnowsItsWellKnownLocation(): void
    {
        // When
        $metadata = ProviderDocument::handler()->handle(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame('https://as.example/.well-known/oauth-authorization-server/acme', $metadata->authorizationServerMetadataUrl());
    }

    #[Test]
    public function theDocumentIsCachedForOneHourByDefault(): void
    {
        // When
        $metadata = ProviderDocument::handler()->handle(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'Cache-Control' => 'public, max-age=3600',
            ],
            $metadata->headers,
        );
    }

    #[Test]
    #[DataProvider('provideLifetimes')]
    public function theLifetimeIsAnOption(int $lifetime, string $cacheControl): void
    {
        // Given
        $handler = ProviderDocument::handler(maxAge: $lifetime);

        // When
        $metadata = $handler->handle(Fixtures::tenant());

        // Then
        static::assertSame(
            [
                'Cache-Control' => $cacheControl,
            ],
            $metadata->headers,
        );
    }

    /**
     * @return iterable<string, array{int, string}>
     */
    public static function provideLifetimes(): iterable
    {
        yield 'one minute' => [60, 'public, max-age=60'];
        yield 'zero' => [0, 'public, max-age=0'];
    }

    #[Test]
    public function aNegativeLifetimeIsRefusedAtConstruction(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('number of seconds');

        // When
        new DiscoveryHandler([], -1);
    }

    #[Test]
    public function itAnnouncesTheSameEncryptionForEveryKindOfDocument(): void
    {
        // When
        $document = ProviderDocument::of();

        // Then
        foreach (['id_token_encryption', 'userinfo_encryption', 'request_object_encryption'] as $member) {
            static::assertSame(['ECDH-ES+A256KW', 'RSA-OAEP-256'], $document[$member . '_alg_values_supported'], $member);
            static::assertSame(['A256GCM'], $document[$member . '_enc_values_supported'], $member);
        }
    }

    #[Test]
    #[DataProvider('provideIssuers')]
    public function itPassesTheChecksOfSymfonyOidcDiscovery(string $issuer): void
    {
        // When
        $document = ProviderDocument::handler()->handle(Fixtures::tenant('acme', $issuer))->toArray();

        // Then
        static::assertSame($issuer, $document['issuer']);
        foreach ([
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'jwks_uri',
            'end_session_endpoint',
            'introspection_endpoint',
            'revocation_endpoint',
        ] as $endpoint) {
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

    /**
     * @param array<string, mixed> $members
     */
    private static function contributor(array $members): MetadataContributorInterface
    {
        return new readonly class($members) implements MetadataContributorInterface {
            /**
             * @param array<string, mixed> $members
             */
            public function __construct(
                private array $members,
            ) {
            }

            public function metadata(Tenant $tenant): array
            {
                return $this->members;
            }
        };
    }
}
