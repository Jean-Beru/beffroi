<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTlsEndpoints;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8705 §5
 */
final class AnnouncedMutualTlsEndpointsTest extends TestCase
{
    #[Test]
    public function theyAreTheEndpointsOnTheHostThatAsksForACertificate(): void
    {
        // Given
        $announced = new AnnouncedMutualTlsEndpoints(new Endpoints('https://mtls.as.example'), Grants::servedWithDeviceCode());

        // When
        $members = $announced->metadata(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame(
            [
                'mtls_endpoint_aliases' => [
                    'token_endpoint' => 'https://mtls.as.example/token',
                    'userinfo_endpoint' => 'https://mtls.as.example/userinfo',
                    'introspection_endpoint' => 'https://mtls.as.example/introspect',
                    'revocation_endpoint' => 'https://mtls.as.example/revoke',
                    'pushed_authorization_request_endpoint' => 'https://mtls.as.example/par',
                    'device_authorization_endpoint' => 'https://mtls.as.example/device_authorization',
                ],
            ],
            $members,
        );
    }

    #[Test]
    public function aProviderWiredWithNoDeviceGrantAliasesNoDeviceAuthorizationEndpoint(): void
    {
        // Given
        $announced = new AnnouncedMutualTlsEndpoints(new Endpoints('https://mtls.as.example'), Grants::served());

        // When
        $members = $announced->metadata(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame(
            [
                'mtls_endpoint_aliases' => [
                    'token_endpoint' => 'https://mtls.as.example/token',
                    'userinfo_endpoint' => 'https://mtls.as.example/userinfo',
                    'introspection_endpoint' => 'https://mtls.as.example/introspect',
                    'revocation_endpoint' => 'https://mtls.as.example/revoke',
                    'pushed_authorization_request_endpoint' => 'https://mtls.as.example/par',
                ],
            ],
            $members,
        );
    }

    /**
     * RFC 8705 §5
     */
    #[Test]
    public function aDeploymentWithoutSuchAHostAnnouncesNoAlias(): void
    {
        // Given
        $announced = new AnnouncedMutualTlsEndpoints(new Endpoints(), Grants::servedWithDeviceCode());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame([], $members);
    }
}
