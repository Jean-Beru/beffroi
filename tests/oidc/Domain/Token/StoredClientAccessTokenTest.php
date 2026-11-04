<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use DateTimeImmutable;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\StoredClientAccessToken;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class StoredClientAccessTokenTest extends TestCase
{
    private Tenant $tenant;

    private Client $client;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->client = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET));
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function itNamesNoPerson(): void
    {
        // Given
        $token = StoredClientAccessToken::fromAuthorization(
            DrawnSecret::digestOf('the-token'),
            $this->authorization(Uuid::v7()),
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );

        // When / Then
        static::assertNull($token->person());
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function itNamesNoSessionForAPerson(): void
    {
        // Given
        $token = StoredClientAccessToken::fromAuthorization(
            DrawnSecret::digestOf('the-token'),
            $this->authorization(Uuid::v7()),
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );

        // When / Then
        static::assertNull($token->sessionNamingItsPerson());
    }

    /**
     * Architecture §4.6, RFC 6749 §4.4
     */
    #[Test]
    public function itRecordsWhatTheIntrospectionOfTheTokenAnswersWith(): void
    {
        // Given
        $grant = Uuid::v7();

        // When
        $token = StoredClientAccessToken::fromAuthorization(
            DrawnSecret::digestOf('the-token'),
            $this->authorization($grant),
            Fixtures::now(),
            Fixtures::now()->modify('+10 minutes'),
        );

        // Then
        static::assertSame(DrawnSecret::digestOf('the-token'), $token->tokenHash);
        static::assertSame($grant, $token->grantId);
        static::assertSame($this->client, $token->client);
        static::assertSame('batch', $token->clientId);
        static::assertSame($this->tenant, $token->tenant);
        static::assertSame(['invoices.read'], $token->scopes->values());
        static::assertSame([Clients::CALENDAR], $token->resources?->values());
        static::assertNull($token->confirmation);
        static::assertEquals(Fixtures::now(), $token->issuedAt);
        static::assertEquals(Fixtures::now()->modify('+10 minutes'), $token->expiresAt);
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function itIsAddressedToTheResourcesItWasAskedFor(): void
    {
        // Given
        $token = $this->token();

        // When / Then
        static::assertSame([Clients::CALENDAR], $token->audience()->values);
    }

    #[Test]
    public function itExpiresAtTheSecondOfItsExpiry(): void
    {
        // Given
        $token = $this->token();

        // When / Then
        static::assertFalse($token->isExpired(Fixtures::now()->modify('+9 minutes 59 seconds')));
        static::assertTrue($token->isExpired(Fixtures::now()->modify('+10 minutes')));
    }

    #[Test]
    public function itRefusesAValueThatIsNotAHexSha256(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An opaque access token is stored as its hex SHA-256.');

        // When
        $this->token(tokenHash: Secrets::draw());
    }

    #[Test]
    public function itRefusesToExpireBeforeItWasIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An access token expires after it was issued.');

        // When
        $this->token(expiresAt: Fixtures::now());
    }

    private function token(?string $tokenHash = null, ?DateTimeImmutable $expiresAt = null): StoredClientAccessToken
    {
        return new StoredClientAccessToken(
            $tokenHash ?? DrawnSecret::digestOf('the-token'),
            Uuid::v7(),
            $this->client,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
            Fixtures::now(),
            $expiresAt ?? Fixtures::now()->modify('+10 minutes'),
        );
    }

    private function authorization(Uuid $grantId): ClientAuthorization
    {
        return new ClientAuthorization(
            Grants::clientCredentials(),
            $grantId,
            $this->client,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
    }
}
