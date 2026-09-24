<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Application\Discovery\Metadata;

use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Application\Client\ClientAuthenticationMethods;
use Heidi\Oidc\Application\Discovery\AnnouncedAlgorithms;
use Heidi\Oidc\Application\Discovery\Metadata\AnnouncedClientAuthentication;
use Heidi\Oidc\Tests\Fixture\FakeClientAuthenticationMethod;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8414 §2: how a client authenticates at the token endpoint, and what an assertion of those methods
 * may be signed with.
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

    /**
     * Open by addition: a method no line of the module knows about is announced with what signs its own
     * assertion, because it is wired and for no other reason (issue #98).
     */
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
