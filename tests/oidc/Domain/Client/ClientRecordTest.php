<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\Metadata\AttestedMembers;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3.2.1
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
        $record = new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', $metadata, [], null, self::digest(), Fixtures::now());

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
        $record = new ClientRecord(Uuid::v7(), $tenant, 'drawn-identifier', [], [], null, self::digest(), Fixtures::now());

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
        new ClientRecord(Uuid::v7(), Fixtures::tenant(), '', [], [], null, self::digest(), Fixtures::now());
    }

    /**
     * RFC 7591 §3.2.1
     */
    #[Test]
    public function aRecordWithoutASecretHasNothingThatExpires(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "drawn-identifier" holds no secret, so nothing of it expires.');

        // When
        new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, self::digest(), Fixtures::now(), Fixtures::now()->modify('+1 day'));
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
            self::digest(),
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
            self::digest(),
            Fixtures::now(),
            $expiresAt,
        );

        // Then
        static::assertEquals($expiresAt, $record->secretExpiresAt);
    }

    /**
     * RFC 7592 §2.3
     */
    #[Test]
    public function theRegistrationAccessTokenIsKeptAsItsDigest(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The registration access token of the client "drawn-identifier" is stored as the hex SHA-256 of its value, never as the value.');

        // When
        new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, Secrets::draw(), Fixtures::now());
    }

    /**
     * RFC 7592 §2.3
     */
    #[Test]
    public function aRecordIsReadWithTheTokenItWasHanded(): void
    {
        // Given
        $record = new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, self::digest(), Fixtures::now());

        // When / Then
        static::assertFalse($record->isReadWith(DrawnSecret::digestOf('a value drawn for somebody else')));
    }

    /**
     * RFC 7592 §2.2
     */
    #[Test]
    public function aReplacementIsTheWholeRegistration(): void
    {
        // Given
        $record = new ClientRecord(
            Uuid::v7(),
            Fixtures::tenant(),
            'drawn-identifier',
            [
                'redirect_uris' => ['https://rp.example/cb'],
                'client_name' => 'What it was called',
            ],
            [
                'requires_pkce' => false,
            ],
            null,
            self::digest(),
            Fixtures::now(),
        );

        // When
        $record->replaceWith(
            [
                'redirect_uris' => ['https://rp.example/elsewhere'],
            ],
            [],
            null,
        );

        // Then
        static::assertSame(
            [
                'redirect_uris' => ['https://rp.example/elsewhere'],
            ],
            $record->metadata,
        );
        static::assertSame([], $record->assigned);
    }

    /**
     * RFC 7592 §2.2
     */
    #[Test]
    public function aReplacementLeavesWhatTheProviderAssigned(): void
    {
        // Given
        $digest = self::digest();
        $record = new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, $digest, Fixtures::now());

        // When
        $record->replaceWith(
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            [],
            null,
        );

        // Then
        static::assertSame('drawn-identifier', $record->clientId);
        static::assertSame($digest, $record->registrationAccessTokenDigest);
        static::assertEquals(Fixtures::now(), $record->issuedAt);
    }

    #[Test]
    public function aReplacementThatLeavesNoSecretLeavesNothingThatExpires(): void
    {
        // Given
        $record = new ClientRecord(
            Uuid::v7(),
            Fixtures::tenant(),
            'drawn-identifier',
            [],
            [],
            new SharedClientSecret('a2b0c5d1e9f4a7b3c8d2e6f0a1b5c9d3'),
            self::digest(),
            Fixtures::now(),
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "drawn-identifier" holds no secret, so nothing of it expires.');

        // When
        $record->replaceWith([], [], null, Fixtures::now()->modify('+1 day'));
    }

    /**
     * RFC 7591 §3.1.1, RFC 7592 §2.2
     */
    #[Test]
    public function whatAStatementSignedIsReadInFrontOfWhatTheClientSends(): void
    {
        // Given
        $attested = [
            'client_name' => 'Invoice reader, attested',
        ];
        $record = new ClientRecord(
            Uuid::v7(),
            Fixtures::tenant(),
            'drawn-identifier',
            $attested,
            [],
            null,
            self::digest(),
            Fixtures::now(),
            attested: $attested,
        );

        // When
        $inFront = $record->attestation();

        // Then
        static::assertEquals([new AttestedMembers($attested)], $inFront);
    }

    #[Test]
    public function aClientNoStatementAttestedHasNothingReadInFrontOfWhatItSends(): void
    {
        // Given
        $record = new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, self::digest(), Fixtures::now());

        // When / Then
        static::assertSame([], $record->attestation());
    }

    private static function digest(): string
    {
        return DrawnSecret::digestOf(Secrets::draw());
    }

    /**
     * Decision 0009
     */
    #[Test]
    public function aRecordKnowsNobodyHasUsedItYet(): void
    {
        // Given
        $record = new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, self::digest(), Fixtures::now());

        // When / Then
        static::assertNull($record->lastUsedAt);
    }

    #[Test]
    public function aRecordKeepsWhenItWasUsed(): void
    {
        // Given
        $record = new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, self::digest(), Fixtures::now());

        // When
        $record->recordUse(Fixtures::now()->modify('+1 hour'));

        // Then
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $record->lastUsedAt);
    }

    #[Test]
    public function theDateOfALastUseOnlyMovesForward(): void
    {
        // Given
        $record = new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, self::digest(), Fixtures::now());
        $record->recordUse(Fixtures::now()->modify('+1 hour'));

        // When
        $record->recordUse(Fixtures::now()->modify('+1 minute'));

        // Then
        static::assertEquals(Fixtures::now()->modify('+1 hour'), $record->lastUsedAt);
    }

    /**
     * RFC 7592 §2.2
     */
    #[Test]
    public function aReplacementIsNotAUse(): void
    {
        // Given
        $record = new ClientRecord(Uuid::v7(), Fixtures::tenant(), 'drawn-identifier', [], [], null, self::digest(), Fixtures::now());

        // When
        $record->replaceWith(
            [
                'redirect_uris' => ['https://rp.example/cb'],
            ],
            [],
            null,
        );

        // Then
        static::assertNull($record->lastUsedAt);
    }
}
