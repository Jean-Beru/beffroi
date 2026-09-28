<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\ClientRecord;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3.2.1: what the provider keeps of a client it registered itself.
 */
final class ClientRecordTest extends TestCase
{
    #[Test]
    public function itKeepsTheMetadataAsTheClientRegisteredIt(): void
    {
        // Given
        $metadata = [
            'redirect_uris' => ['https://registered.example/callback'],
            'token_endpoint_auth_method' => 'none',
        ];

        // When
        $record = new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', $metadata, [], null, Fixtures::now());

        // Then
        static::assertSame($metadata, $record->metadata);
        static::assertNull($record->secret);
        static::assertNull($record->secretExpiresAt);
    }

    #[Test]
    public function aRecordBelongsToTheTenantItWasRegisteredUnder(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $record = new ClientRecord(Uuid::v7(), $tenant, 'drawn-identifier', [], [], null, Fixtures::now());

        // When / Then
        static::assertFalse($record->belongsTo(Fixtures::tenant('other', 'https://id.other.example')));
    }

    #[Test]
    public function aRecordCarriesTheIdentifierTheProviderDrew(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A registered client carries the identifier the provider drew for it (RFC 7591 section 3.2.1).');

        // When
        new ClientRecord(Uuid::v7(), Fixtures::tenant(), '', [], [], null, Fixtures::now());
    }

    /**
     * RFC 7591 §3.2.1: "client_secret_expires_at" is about a secret, so a client that holds none has
     * nothing that expires.
     */
    #[Test]
    public function aRecordWithoutASecretHasNothingThatExpires(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "drawn-identifier" holds no secret, so nothing of it expires.');

        // When
        new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, Fixtures::now(), Fixtures::now()->modify('+1 day'));
    }

    #[Test]
    public function aSecretExpiresAfterItWasIssued(): void
    {
        // Given
        $issuedAt = Fixtures::now();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The secret of the client "drawn-identifier" expires after it was issued.');

        // When
        new ClientRecord(
            Uuid::v7(),
            Fixtures::tenant(),
            'drawn-identifier',
            [],
            [],
            new SharedClientSecret('a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3'),
            $issuedAt,
            $issuedAt,
        );
    }

    #[Test]
    public function aSecretThatExpiresLaterIsKeptWithItsDate(): void
    {
        // Given
        $expiresAt = Fixtures::now()->modify('+30 days');

        // When
        $record = new ClientRecord(
            Uuid::v7(),
            Fixtures::tenant(),
            'drawn-identifier',
            [],
            [],
            new SharedClientSecret('a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3'),
            Fixtures::now(),
            $expiresAt,
        );

        // Then
        static::assertEquals($expiresAt, $record->secretExpiresAt);
    }
}
