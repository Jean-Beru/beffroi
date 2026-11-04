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
 * OIDC Core §8.1, CIBA Core §4
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
     * CIBA Core §4
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
     * OIDC Core §8.1
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
     * CIBA Core §4
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
     * OIDC Registration §5
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
     * CIBA Core §4
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
