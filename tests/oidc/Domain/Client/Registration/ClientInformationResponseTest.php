<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client\Registration;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\ClientSecretInterface;
use Heidi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3.2.1 and RFC 7592 §3: what the provider answers a client about itself, the two being the same
 * body.
 */
final class ClientInformationResponseTest extends TestCase
{
    private const string URI = 'https://id.acme.example/register/drawn-identifier';

    #[Test]
    public function itAnswersTheIdentifierTheDateAndWhatWasRegistered(): void
    {
        // Given
        $response = new ClientInformationResponse(ClientInformationResponse::INFORMED, self::record(), self::URI);

        // When
        $parameters = $response->parameters();

        // Then
        static::assertSame(
            [
                'client_id' => 'drawn-identifier',
                'client_id_issued_at' => Fixtures::now()->getTimestamp(),
                'registration_client_uri' => self::URI,
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            $parameters,
        );
    }

    /**
     * RFC 7591 §3.2.1: "client_secret_expires_at" is required whenever a secret is answered, and 0 is what
     * says the secret does not expire.
     */
    #[Test]
    public function aSecretIsAnsweredWithTheDateItDoesNotExpireOn(): void
    {
        // Given
        $response = new ClientInformationResponse(
            ClientInformationResponse::REGISTERED,
            self::record(new SharedClientSecret('a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3')),
            self::URI,
            'the-drawn-value',
        );

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
        $response = new ClientInformationResponse(ClientInformationResponse::REGISTERED, self::record(), self::URI);

        // When
        $parameters = $response->parameters();

        // Then
        static::assertArrayNotHasKey('client_secret', $parameters);
        static::assertArrayNotHasKey('client_secret_expires_at', $parameters);
    }

    /**
     * RFC 7591 §3.2.1, RFC 7592 §3: a registration hands out the two credentials once, and the URI it hands
     * with them is where the client will present the other.
     */
    #[Test]
    public function aRegistrationAnswersTheTokenAndTheUriItWasDrawnFor(): void
    {
        // Given
        $response = new ClientInformationResponse(
            ClientInformationResponse::REGISTERED,
            self::record(),
            self::URI,
            null,
            'the-drawn-token',
        );

        // When
        $parameters = $response->parameters();

        // Then
        static::assertSame('the-drawn-token', $parameters['registration_access_token']);
        static::assertSame(self::URI, $parameters['registration_client_uri']);
    }

    /**
     * RFC 7592 §2.3 permits rotating the token on every answer and does not require it, so a client that
     * reads itself is answered the URI and keeps the token it was handed.
     */
    #[Test]
    public function aClientThatReadsItselfIsAnsweredNoTokenAgain(): void
    {
        // Given
        $response = new ClientInformationResponse(ClientInformationResponse::INFORMED, self::record(), self::URI);

        // When
        $parameters = $response->parameters();

        // Then
        static::assertArrayNotHasKey('registration_access_token', $parameters);
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
            DrawnSecret::digestOf(Secrets::draw()),
            Fixtures::now(),
        );
    }
}
