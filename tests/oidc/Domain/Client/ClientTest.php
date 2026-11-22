<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Domain\Client;

use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Client\SharedClientSecret;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Beffroi\Oidc\Tests\Fixture\Shapes;

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
     * OIDC Core §9
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
                new ClientPresentation('Name'),
                Methods::clientSecretBasic(),
                true,
                [new RedirectUri('https://rp.example/cb')],
                Shapes::jwt(),
            ),
            new SharedClientSecret(Clients::SECRET),
        );
    }

    #[Test]
    public function aClientCannotContradictWhatItsRegistrationDeclares(): void
    {
        // Given
        $registration = new ClientRegistration(
            'demo',
            new ClientPresentation('Demo'),
            Methods::clientSecretBasic(),
            true,
            [new RedirectUri('https://rp.example/cb')],
            Shapes::jwt(),
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('The client "demo" is built with a secret its registration does not declare, or without the one it does.');

        // When
        new Client(Fixtures::tenant(), $registration);
    }
}
