<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client\Registration;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\ClientSecretInterface;
use Beffroi\Oidc\Domain\Client\Registration\ClientInformationResponse;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3.2.1, RFC 7592 §3
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
     * RFC 7591 §3.2.1
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
     * RFC 7591 §3.2.1, RFC 7592 §3
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
     * RFC 7592 §2.3
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
