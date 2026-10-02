<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

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
 * RFC 7662 §2.1: where a resource server asks about a token, and how it authenticates there. RFC 9701 §6
 * adds what a signed introspection response is signed with.
 */
final class AnnouncedIntrospectionTest extends TestCase
{
    /**
     * RFC 7662 §2.1: introspection takes the methods that authenticate the caller, among those the
     * provider takes; a public client has none, so "none" is not announced here.
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
                'introspection_signing_alg_values_supported' => ['RS256', 'PS256', 'ES256', 'EdDSA'],
            ],
            $members,
        );
    }

    /**
     * What a caller's assertion may be signed with is read from the methods kept, not from those the
     * token endpoint takes.
     */
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

    private static function announced(ClientAuthenticationMethods $methods): AnnouncedIntrospection
    {
        return new AnnouncedIntrospection(
            new Endpoints(),
            $methods,
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()),
        );
    }
}
