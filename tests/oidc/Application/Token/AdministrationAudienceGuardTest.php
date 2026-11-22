<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Token;

use Beffroi\Core\Bridge\InMemory\InMemoryGroupMembershipRepository;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Token\AdministrationAudienceGuard;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Resource\ResourceIndicator;
use Beffroi\Oidc\Domain\Resource\ResourceIndicators;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Token\AddressedAccessToken;
use Beffroi\Oidc\Domain\Token\ClientAuthorization;
use Beffroi\Oidc\Exception\InvalidTargetException;
use Beffroi\Oidc\Tests\Fixture\Administrations;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\FakeAccessTokenIssuer;
use Beffroi\Oidc\Tests\Fixture\Grants;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0038: every access token is minted under the reservation of the administration API, whichever grant asks.
 */
final class AdministrationAudienceGuardTest extends TestCase
{
    private Client $client;

    private FakeAccessTokenIssuer $issuer;

    private AdministrationAudienceGuard $guard;

    protected function setUp(): void
    {
        $tenant = Fixtures::tenant();
        $this->client = Clients::service(
            $tenant,
            new FakePasswordHasher()->hash(Clients::SECRET),
            resources: [new ResourceIndicator(Administrations::RESOURCE), new ResourceIndicator(Clients::CALENDAR)],
        );
        $this->issuer = new FakeAccessTokenIssuer();
        $this->guard = new AdministrationAudienceGuard($this->issuer, Administrations::of($tenant, new InMemoryGroupMembershipRepository()));
    }

    /**
     * RFC 6749 §4.4: a client acting for itself has nobody behind its token, and the issuer it guards mints nothing.
     */
    #[Test]
    public function aTokenTheReservationRefusesIsNeverMinted(): void
    {
        // Given
        $authorization = $this->clientActingForItselfFor(Administrations::RESOURCE);

        // When
        try {
            $this->guard->issue($authorization, new AddressedAccessToken(), Fixtures::now());
            static::fail('A token was addressed to the administration API for a client acting for itself.');
        } catch (InvalidTargetException) {
        }

        // Then
        static::assertSame([], $this->issuer->issued);
    }

    #[Test]
    public function aTokenForAnotherResourceIsMintedByTheIssuerItGuards(): void
    {
        // Given
        $authorization = $this->clientActingForItselfFor(Clients::CALENDAR);

        // When
        $this->guard->issue($authorization, new AddressedAccessToken(), Fixtures::now());

        // Then
        static::assertSame([$authorization], $this->issuer->issued);
    }

    private function clientActingForItselfFor(string $resource): ClientAuthorization
    {
        return new ClientAuthorization(
            Grants::clientCredentials(),
            Uuid::v7(),
            $this->client,
            new Scopes([new Scope('invoices.read')]),
            ResourceIndicators::of([$resource]),
        );
    }
}
