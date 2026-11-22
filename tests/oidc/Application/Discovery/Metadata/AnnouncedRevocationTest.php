<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedRevocation;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7009 §2.1
 */
final class AnnouncedRevocationTest extends TestCase
{
    #[Test]
    public function itNamesTheEndpointOfTheTenantAndHowAClientAuthenticatesThere(): void
    {
        // Given
        $announced = new AnnouncedRevocation(
            new Endpoints(),
            Methods::all(),
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()),
        );

        // When
        $members = $announced->metadata(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame(
            [
                'revocation_endpoint' => 'https://as.example/acme/revoke',
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
            ],
            $members,
        );
    }
}
