<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Token;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\AuthorizationInterface;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Domain\Token\StoredAccessToken;
use Beffroi\Oidc\Domain\Token\StoredClientAccessToken;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class ClientAuthorizationTest extends TestCase
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
    public function itStandsOnWhatTheClientRegistered(): void
    {
        // When
        $authorization = $this->authorization(new Scopes([new Scope('invoices.read')]));

        // Then
        static::assertSame($this->client, $authorization->client);
        static::assertSame($this->tenant, $authorization->tenant);
        static::assertTrue($authorization->grantType->equals(Grants::clientCredentials()));
        static::assertSame(['invoices.read'], $authorization->scopes->values());
        static::assertSame(['invoices.read', 'invoices.write'], $authorization->grantedScopes->values());
        static::assertSame([Clients::CALENDAR], $authorization->resources->values());
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $authorization->grantedResources->values());
        static::assertNull($authorization->confirmation);
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function theAccessTokenIsAddressedToTheResourcesAsked(): void
    {
        // When
        $audience = $this->authorization(resources: ResourceIndicators::of([Clients::CALENDAR, Clients::CONTACTS]))->audience();

        // Then
        static::assertSame([Clients::CALENDAR, Clients::CONTACTS], $audience->values);
    }

    /**
     * Architecture §4.6
     */
    #[Test]
    public function itIsKeptAsATokenNobodySignedInFor(): void
    {
        // Given
        $authorization = $this->authorization();

        // When
        $record = self::keptBy($authorization);

        // Then
        static::assertInstanceOf(StoredClientAccessToken::class, $record);
        static::assertSame($authorization->grantId, $record->grantId);
        static::assertSame([Clients::CALENDAR], $record->resources?->values());
    }

    private static function keptBy(AuthorizationInterface $authorization): StoredAccessToken
    {
        return $authorization->storedUnder(str_repeat('a', 64), Fixtures::now(), Fixtures::now()->modify('+10 minutes'));
    }

    /**
     * RFC 6749 §4.4
     */
    #[Test]
    public function itRefusesAPublicClient(): void
    {
        // Given
        $client = Clients::public($this->tenant, resources: Clients::resources(), grantTypes: [Grants::clientCredentials()]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('An authorization with nobody behind it is granted to a client that authenticates itself (RFC 6749 section 4.4).');

        // When
        new ClientAuthorization(Grants::clientCredentials(), Uuid::v7(), $client, new Scopes([Scope::openid()]), ResourceIndicators::of([Clients::CALENDAR]));
    }

    /**
     * RFC 6749 §3.3
     */
    #[Test]
    public function itRefusesAScopeTheClientDidNotRegister(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The scopes of a response are among the ones the client registered (RFC 6749 section 3.3).');

        // When
        $this->authorization(new Scopes([new Scope('payroll.read')]));
    }

    /**
     * RFC 8707 §2.1
     */
    #[Test]
    public function itRefusesAResourceTheClientDidNotRegister(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The resources of a response are among the ones the client registered (RFC 8707 section 2.1).');

        // When
        $this->authorization(resources: ResourceIndicators::of(['https://payroll.example.com/']));
    }

    /**
     * RFC 8707 §2
     */
    #[Test]
    public function itRefusesAClientThatRegisteredNoResource(): void
    {
        // Given
        $client = Clients::service($this->tenant, new FakePasswordHasher()->hash(Clients::SECRET), resources: []);

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $client,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([Clients::CALENDAR]),
        );
    }

    private function authorization(?Scopes $scopes = null, ?ResourceIndicators $resources = null): ClientAuthorization
    {
        return new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $this->client,
            $scopes ?? new Scopes([new Scope('invoices.read')]),
            $resources ?? new ResourceIndicators([new ResourceIndicator(Clients::CALENDAR)]),
        );
    }
}
