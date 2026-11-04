<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Discovery\Metadata\ProviderIdentity;
use Beffroi\Oidc\Tests\Fixture\Endpoints;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Discovery §3
 */
final class ProviderIdentityTest extends TestCase
{
    #[Test]
    public function itNamesTheIssuerAndTheEndpointsOfTheTenant(): void
    {
        // Given
        $identity = new ProviderIdentity(new Endpoints());

        // When
        $members = $identity->metadata(Fixtures::tenant('acme', 'https://as.example/acme'));

        // Then
        static::assertSame(
            [
                'issuer' => 'https://as.example/acme',
                'authorization_endpoint' => 'https://as.example/acme/authorize',
                'token_endpoint' => 'https://as.example/acme/token',
                'userinfo_endpoint' => 'https://as.example/acme/userinfo',
                'jwks_uri' => 'https://as.example/acme/jwks',
            ],
            $members,
        );
    }
}
