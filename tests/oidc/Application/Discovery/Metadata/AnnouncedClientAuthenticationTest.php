<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Discovery\Metadata;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Client\ClientAuthenticationMethods;
use Beffroi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Beffroi\Oidc\Application\Discovery\Metadata\AnnouncedClientAuthentication;
use Beffroi\Oidc\Tests\Fixture\FakeClientAuthenticationMethod;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8414 §2
 */
final class AnnouncedClientAuthenticationTest extends TestCase
{
    #[Test]
    public function theMethodsAndTheirAssertionAlgorithmsAreThoseWired(): void
    {
        // Given
        $announced = self::announced(Methods::all());

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(
            [
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
            ],
            $members,
        );
    }

    #[Test]
    public function aMethodTheModuleKnowsNothingAboutIsAnnouncedBecauseItIsWired(): void
    {
        // Given
        $announced = self::announced(new ClientAuthenticationMethods([new FakeClientAuthenticationMethod()]));

        // When
        $members = $announced->metadata(Fixtures::tenant());

        // Then
        static::assertSame(['smoke_signal'], $members['token_endpoint_auth_methods_supported']);
        static::assertSame(['SM256'], $members['token_endpoint_auth_signing_alg_values_supported']);
    }

    private static function announced(ClientAuthenticationMethods $methods): AnnouncedClientAuthentication
    {
        return new AnnouncedClientAuthentication(
            $methods,
            new AnnouncedAlgorithms(Algorithms::all(), Algorithms::keyEncryption(), Algorithms::contentEncryption()),
        );
    }
}
