<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedMutualTlsEndpoints;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8705 §5: the aliases are the endpoints of the tenant, located a second time by the integration on
 * the host whose listener asks for a client certificate. They are derived from the endpoints and not
 * kept beside them: the paths are the same and only the origin differs.
 */
final class AnnouncedMutualTlsEndpointsTest extends TestCase
{
    #[Test]
    public function theyAreTheEndpointsOnTheHostThatAsksForACertificate(): void
    {
        // Given
        $announced = new AnnouncedMutualTlsEndpoints(new Endpoints('https://mtls.as.example'));

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

    /**
     * RFC 8705 §5: a deployment that serves no such host announces no alias at all, rather than aliases
     * naming the ordinary endpoints.
     */
    #[Test]
    public function aDeploymentWithoutSuchAHostAnnouncesNoAlias(): void
    {
        // Given
        $announced = new AnnouncedMutualTlsEndpoints(new Endpoints());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame([], $members);
    }
}
