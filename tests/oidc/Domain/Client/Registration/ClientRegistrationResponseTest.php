<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client\Registration;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\Registration\ClientRegistrationResponse;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3.2.1: what the endpoint answers a client it registered.
 */
final class ClientRegistrationResponseTest extends TestCase
{
    #[Test]
    public function itAnswersTheIdentifierTheDateAndWhatWasRegistered(): void
    {
        // Given
        $response = new ClientRegistrationResponse(self::record());

        // When
        $parameters = $response->parameters();

        // Then
        static::assertSame(
            [
                'client_id' => 'drawn-identifier',
                'client_id_issued_at' => Fixtures::now()->getTimestamp(),
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            $parameters,
        );
    }

    /**
     * RFC 7591 §3.2.1: "client_secret_expires_at" is required whenever a secret is answered, and 0 is
     * what says the secret does not expire.
     */
    #[Test]
    public function aSecretIsAnsweredWithTheDateItDoesNotExpireOn(): void
    {
        // Given
        $response = new ClientRegistrationResponse(self::record(new SharedClientSecret('a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3')), 'the-drawn-value');

        // When
        $parameters = $response->parameters();

        // Then
        static::assertSame('the-drawn-value', $parameters['client_secret']);
        static::assertSame(0, $parameters['client_secret_expires_at']);
    }

    /**
     * A client whose method proves no secret is answered none, and nothing of it expires.
     */
    #[Test]
    public function aClientWithoutASecretIsAnsweredNone(): void
    {
        // Given
        $response = new ClientRegistrationResponse(self::record());

        // When
        $parameters = $response->parameters();

        // Then
        static::assertArrayNotHasKey('client_secret', $parameters);
        static::assertArrayNotHasKey('client_secret_expires_at', $parameters);
    }

    private static function record(?ClientSecretInterface $secret = null): ClientRecord
    {
        return new ClientRecord(
            Uuid::v7(),
            Fixtures::tenant(),
            'drawn-identifier',
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            [],
            $secret,
            Fixtures::now(),
        );
    }
}
