<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Token;

use Heidi\Oidc\Tests\Fixture\Secrets;
use DateTimeImmutable;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Resource\ResourceIndicators;
use Heidi\Oidc\Domain\Scope\Scope;
use Heidi\Oidc\Domain\Scope\Scopes;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Domain\Token\ClientAuthorization;
use Heidi\Oidc\Domain\Token\StoredClientAccessToken;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Grants;
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
     * Architecture §4.6: the row keeps what the introspection of the token answers with, and nothing of a
     * sign-in, there having been none (RFC 6749 §4.4).
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
     * RFC 8707 §2: the token is addressed to the resources it was asked for, never to its own client.
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
