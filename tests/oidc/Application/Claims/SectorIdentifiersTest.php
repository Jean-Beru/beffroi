<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Claims;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\Sector\RedirectUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\SectorIdentifiers;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Sectors;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * OIDC Core §8.1 and CIBA Core §4: which sector a client is of, read through every source the deployment
 * wired, in the order it wired them.
 */
final class SectorIdentifiersTest extends TestCase
{
    private const string SECRET_HASH_SOURCE = Clients::SECRET;

    /**
     * @param callable(Tenant): ClientRegistration $registration
     */
    #[Test]
    #[DataProvider('provideRegistrations')]
    public function itIsTheHostTheRegistrationNames(callable $registration, string $host): void
    {
        // Given
        $sectors = Sectors::ofAProvider();

        // When
        $sector = $sectors->sectorOf($registration(Fixtures::tenant()));

        // Then
        static::assertSame($host, $sector->host);
    }

    /**
     * @return iterable<string, array{callable(Tenant): ClientRegistration, string}>
     */
    public static function provideRegistrations(): iterable
    {
        yield 'the host of the one redirection URI (OIDC Core 8.1)' => [
            static fn (Tenant $tenant): ClientRegistration => Clients::pairwise($tenant, redirectUri: 'https://rp.example/callback')->registration,
            'rp.example',
        ];

        yield 'the host of the sector identifier document, whatever the redirection URI says' => [
            static fn (Tenant $tenant): ClientRegistration => Clients::pairwise(
                $tenant,
                redirectUri: 'https://rp.example/callback',
                sectorIdentifierUri: 'https://sector.example/redirect_uris.json',
            )->registration,
            'sector.example',
        ];

        yield 'a host with a port, which is no part of a sector' => [
            static fn (Tenant $tenant): ClientRegistration => Clients::pairwise($tenant, redirectUri: 'https://rp.example:8443/callback')->registration,
            'rp.example',
        ];

        yield 'the host of the jwks_uri of a client that registers no redirection URI (CIBA Core 4)' => [
            static fn (Tenant $tenant): ClientRegistration => self::backchannel($tenant, jwksUri: 'https://terminal.example/jwks.json')->registration,
            'terminal.example',
        ];

        yield 'the document of a client that registers no redirection URI, before its jwks_uri' => [
            static fn (Tenant $tenant): ClientRegistration => self::backchannel(
                $tenant,
                jwksUri: 'https://terminal.example/jwks.json',
                sectorIdentifierUri: 'https://sector.example/redirect_uris.json',
            )->registration,
            'sector.example',
        ];
    }

    /**
     * CIBA Core §4: two clients of the backchannel flow whose keys are published on one host are of one
     * sector, and see a user under one identifier, as two clients whose browsers come back to one host do.
     */
    #[Test]
    public function twoBackchannelClientsOfOneHostShareOneSector(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $sectors = Sectors::ofAProvider();

        // When
        $one = $sectors->sectorOf(self::backchannel($tenant, 'one', 'https://terminal.example/jwks.json')->registration);
        $other = $sectors->sectorOf(self::backchannel($tenant, 'other', 'https://terminal.example/keys.json')->registration);

        // Then
        static::assertTrue($one->equals($other));
    }

    #[Test]
    public function twoBackchannelClientsOfTwoHostsAreOfTwoSectors(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $sectors = Sectors::ofAProvider();

        // When
        $one = $sectors->sectorOf(self::backchannel($tenant, 'one', 'https://terminal.example/jwks.json')->registration);
        $other = $sectors->sectorOf(self::backchannel($tenant, 'other', 'https://other.example/jwks.json')->registration);

        // Then
        static::assertFalse($one->equals($other));
    }

    /**
     * The "jwks_uri" stands in for a client that registers no redirection URI, and for no other: a client
     * whose browser comes back somewhere is of the sector it comes back to, whatever its keys say, so an
     * ordinary client is never given the sector of its keys by accident.
     */
    #[Test]
    public function aClientThatRegistersARedirectionUriIsOfItsHostAndNotOfItsKeys(): void
    {
        // Given
        $tenant = Fixtures::tenant();
        $registration = Clients::withKeys($tenant, jwksUri: new ClientUri('https://keys.example/jwks.json'))->registration;

        // When
        $sector = Sectors::ofAProvider()->sectorOf($registration);

        // Then
        static::assertSame('key.example', $sector->host);
    }

    /**
     * OIDC Core §8.1: a client whose redirection URIs are on several hosts registers a
     * "sector_identifier_uri" to say which sector it belongs to, and is refused rather than assigned an
     * identifier computed from whichever host came first.
     */
    #[Test]
    public function aClientOnSeveralHostsAndWithoutADocumentNamesNoSector(): void
    {
        // Given
        $onTwoHosts = self::onTwoHosts();

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers redirection URIs on one.example and other.example');

        // When
        Sectors::ofAProvider()->sectorOf($onTwoHosts);
    }

    /**
     * CIBA Core §4: a client of the backchannel flow that registers neither a "sector_identifier_uri" nor a
     * "jwks_uri" registers nothing any wired source reads, and is refused rather than served a "sub"
     * nobody can compute.
     */
    #[Test]
    public function aClientThatRegistersNeitherADocumentNorKeysNamesNoSector(): void
    {
        // Given
        $service = self::backchannel(Fixtures::tenant());

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers nothing that says which sector its subject identifiers belong to');

        // When
        Sectors::ofAProvider()->sectorOf($service->registration);
    }

    /**
     * There is no last resort: a deployment that wires one way of saying it reads that one, and a client
     * that says it another way is refused rather than read by something nobody wired.
     */
    #[Test]
    public function aWayOfSayingItThatNobodyWiredReadsNothing(): void
    {
        // Given
        $registration = self::backchannel(Fixtures::tenant(), jwksUri: 'https://terminal.example/jwks.json')->registration;
        $withoutTheBackchannelSource = new SectorIdentifiers([new RedirectUriSectorIdentifier()]);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers nothing that says which sector');

        // When
        $withoutTheBackchannelSource->sectorOf($registration);
    }

    /**
     * OIDC Registration §5: what a client publishes to back its claim is what it would otherwise have been
     * judged on, which for an ordinary client is every redirection URI it registered.
     */
    #[Test]
    public function aClientPublishesTheRedirectionUrisItsSectorWouldHaveBeenReadFrom(): void
    {
        // Given
        $registration = Clients::pairwise(
            Fixtures::tenant(),
            redirectUri: 'https://rp.example/callback',
            sectorIdentifierUri: 'https://sector.example/redirect_uris.json',
        )->registration;

        // When
        $published = Sectors::ofAProvider()->publishedUris($registration);

        // Then
        static::assertSame(['https://rp.example/callback'], $published);
    }

    /**
     * CIBA Core §4: and for a client that registers no redirection URI, the "jwks_uri" its sector would
     * have been read from instead.
     */
    #[Test]
    public function aBackchannelClientPublishesTheJwksUriItsSectorWouldHaveBeenReadFrom(): void
    {
        // Given
        $registration = self::backchannel(
            Fixtures::tenant(),
            jwksUri: 'https://terminal.example/jwks.json',
            sectorIdentifierUri: 'https://sector.example/redirect_uris.json',
        )->registration;

        // When
        $published = Sectors::ofAProvider()->publishedUris($registration);

        // Then
        static::assertSame(['https://terminal.example/jwks.json'], $published);
    }

    /**
     * An ordinary client's keys are not what its sector is read from, so the document of its sector has no
     * business naming them: a client that publishes its keys behind a URI and registers a document
     * publishes its redirection URIs there and nothing else.
     */
    #[Test]
    public function anOrdinaryClientPublishesNothingOfItsKeys(): void
    {
        // Given
        $registration = Clients::withKeys(
            Fixtures::tenant(),
            jwksUri: new ClientUri('https://keys.example/jwks.json'),
            sectorIdentifierUri: 'https://sector.example/redirect_uris.json',
        )->registration;

        // When
        $published = Sectors::ofAProvider()->publishedUris($registration);

        // Then
        static::assertSame(['https://key.example/callback'], $published);
    }

    private static function backchannel(
        Tenant $tenant,
        string $clientId = 'payment-terminal',
        ?string $jwksUri = null,
        ?string $sectorIdentifierUri = null,
    ): Client {
        return Clients::backchannel(
            $tenant,
            new FakePasswordHasher()->hash(self::SECRET_HASH_SOURCE),
            $clientId,
            jwksUri: $jwksUri,
            sectorIdentifierUri: $sectorIdentifierUri,
        );
    }

    private static function onTwoHosts(): ClientRegistration
    {
        $registration = Clients::pairwise(Fixtures::tenant(), 'two-hosts', 'https://one.example/callback')->registration;

        return new ClientRegistration(
            $registration->clientId,
            $registration->presentation,
            $registration->authenticationMethod,
            false,
            [...$registration->redirectUris, new RedirectUri('https://other.example/callback')],
            $registration->accessTokenShape,
            subjectType: $registration->subjectType,
        );
    }
}
