<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Bridge\JwtLibrary\JoseSignatureAlgorithms;
use Beffroi\Core\Port\SignatureAlgorithmsInterface;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\ClientAuthenticationMethods;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedIntrospection;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7662 §2.1, RFC 9701 §7
 */
final class AnnouncedIntrospectionTest extends TestCase
{
    /**
     * RFC 7662 §2.1
     */
    #[Test]
    public function itTakesTheAuthenticatingMethodsAmongThoseWired(): void
    {
        // Given
        $announced = self::announced(new ClientAuthenticationMethods([Methods::clientSecretPost(), Methods::none()]));

        // When
        $members = $announced->metadata(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame(
            [
                'introspection_endpoint' => 'https://as.example/acme/introspect',
                'introspection_endpoint_auth_methods_supported' => ['client_secret_post'],
                'introspection_endpoint_auth_signing_alg_values_supported' => [],
                'introspection_signing_alg_values_supported' => ['RS256'],
            ],
            $members,
        );
    }

    /**
     * RFC 9701 §6, §7
     */
    #[Test]
    public function aSignedResponseIsAnnouncedUnderTheOneAlgorithmItIsSignedWith(): void
    {
        // Given
        $announced = self::announced(Methods::all(), new JoseSignatureAlgorithms([Algorithms::es256(), Algorithms::rs256()]));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['ES256'], $members['introspection_signing_alg_values_supported']);
    }

    #[Test]
    public function theAssertionAlgorithmsAreThoseOfTheMethodsKept(): void
    {
        // Given
        $announced = self::announced(Methods::all());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'client_secret_jwt', 'tls_client_auth', 'self_signed_tls_client_auth'],
            $members['introspection_endpoint_auth_methods_supported'],
        );
        static::assertSame(['RS256', 'PS256', 'ES256', 'EdDSA', 'HS256'], $members['introspection_endpoint_auth_signing_alg_values_supported']);
    }

    private static function announced(
        ClientAuthenticationMethods $methods,
        ?SignatureAlgorithmsInterface $signature = null,
    ): AnnouncedIntrospection {
        return new AnnouncedIntrospection(
            new Endpoints(),
            $methods,
            new AnnouncedAlgorithms($signature ?? Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()),
        );
    }
}
