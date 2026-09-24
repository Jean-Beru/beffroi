<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Client;

use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\HashedClientSecret;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\SharedClientSecret;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use Heidi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * A registration bound to a tenant, with its shared secret in the shape the provider keeps it. What a
 * registration holds to is checked by ClientRegistrationTest; what is checked here is the one thing
 * only a client can see, the secret it was handed.
 */
final class ClientTest extends TestCase
{
    #[Test]
    public function aConfidentialClientHoldsAHashedSecret(): void
    {
        // Given
        $hash = new FakePasswordHasher()->hash(Clients::SECRET);

        // When
        $client = Clients::confidential(Fixtures::tenant(), $hash);

        // Then
        static::assertFalse($client->registration->isPublic());
        static::assertInstanceOf(HashedClientSecret::class, $client->secret);
        static::assertSame($hash, $client->secret->hash);
        static::assertSame('client_secret_basic', $client->registration->authenticationMethod->name());
    }

    #[Test]
    public function aClientBelongsToItsTenantOnly(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $client = Clients::public($tenant);

        // When / Then
        static::assertTrue($client->belongsTo($tenant));
        static::assertFalse($client->belongsTo(Fixtures::tenant('other')));
    }

    /**
     * A client identifier is unique within its tenant: two registrations of the same identifier in two
     * tenants are two clients.
     */
    #[Test]
    public function itEqualsTheSameRegistrationOfItsTenant(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $client = Clients::public($tenant);

        // When / Then
        static::assertTrue($client->equals(Clients::public($tenant)));
        static::assertFalse($client->equals(Clients::public($tenant, 'another')));
        static::assertFalse($client->equals(Clients::public(Fixtures::tenant('other', 'https://id.other.example'))));
    }

    /**
     * OIDC Core §9: "client_secret_basic" is shown the secret and keeps a hash of it;
     * "client_secret_jwt" computes a MAC with it and keeps the secret. A secret kept for one is not a
     * secret the other verifies against.
     */
    #[Test]
    public function aSecretIsKeptInTheShapeTheRegisteredMethodVerifiesAgainst(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('is not kept in a shape client_secret_basic verifies against');

        // When
        new Client(
            Fixtures::tenant(),
            new ClientRegistration(
                'demo',
                'Name',
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://rp.example/cb')],
            ),
            new SharedClientSecret(Clients::SECRET),
        );
    }

    /**
     * A registration says whether the client registered a shared secret. A client built against it with
     * the other answer is a wiring fault, not a client: the two would disagree on what authenticates it.
     */
    #[Test]
    public function aClientCannotContradictWhatItsRegistrationDeclares(): void
    {
        // Given
        $registration = new ClientRegistration('demo', 'Demo', Methods::clientSecretBasic(), true, [new RedirectUri('https://rp.example/cb')]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "demo" is built with a secret its registration does not declare, or without the one it does.');

        // When
        new Client(Fixtures::tenant(), $registration);
    }
}
