<?php

declare(strict_types=1);

namespace Beffroi\Oidc\Tests\Application\Claims;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Application\Claims\Sector\RedirectUriSectorIdentifier;
use Beffroi\Oidc\Application\Claims\SectorIdentifiers;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Application\Claims\PairwiseSubjectIdentifierResolver;
use Beffroi\Oidc\Domain\Client\ClientAuthenticationMethodInterface;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\ClientUri;
use Beffroi\Oidc\Domain\Client\GrantTypeName;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Exception\InvalidArgumentException;
use Beffroi\Oidc\Tests\Fixture\Clients;
use Beffroi\Oidc\Tests\Fixture\Grants;
use Beffroi\Oidc\Tests\Fixture\Methods;
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
        $this->expectExceptionMessageIsOrContains('registers redirection and login URIs on one.example and other.example');

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

    /**
     * CIBA Core §4
     */
    #[Test]
    #[DataProvider('provideMethodsThatHoldNoKey')]
    public function theJwksUriOfAClientThatAuthenticatesWithoutAKeyNamesNoSector(ClientAuthenticationMethodInterface $method): void
    {
        // Given
        $registration = self::backchannel(Fixtures::tenant(), jwksUri: 'https://terminal.example/jwks.json', method: $method)->registration;

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers nothing that says which sector its subject identifiers belong to');

        // When
        Sectors::ofAProvider()->sectorOf($registration);
    }

    /**
     * @return iterable<string, array{ClientAuthenticationMethodInterface}>
     */
    public static function provideMethodsThatHoldNoKey(): iterable
    {
        yield 'a secret' => [Methods::clientSecretBasic()];
        yield 'nothing at all' => [Methods::none()];
    }

    /**
     * CIBA Core §4
     */
    #[Test]
    public function aClientThatAuthenticatesWithItsCertificateIsOfTheHostOfItsKeys(): void
    {
        // Given
        $registration = self::backchannel(
            Fixtures::tenant(),
            jwksUri: 'https://terminal.example/jwks.json',
            method: Methods::selfSignedTlsClientAuth(),
        )->registration;

        // When
        $sector = Sectors::ofAProvider()->sectorOf($registration);

        // Then
        static::assertSame('terminal.example', $sector->host);
    }

    /**
     * CIBA Core §4, RFC 8628 §3.4
     *
     * @param list<GrantTypeName> $grantTypes
     */
    #[Test]
    #[DataProvider('provideGrantsWithoutARedirection')]
    public function aClientAGrantReachesWithoutARedirectionIsOfTheHostOfItsKeysAndNotOfItsRedirection(array $grantTypes): void
    {
        // Given
        $registration = self::reachedWithoutARedirection($grantTypes, Methods::privateKeyJwt(), 'https://keys.example/jwks.json')->registration;

        // When
        $sector = Sectors::ofAProvider()->sectorOf($registration);

        // Then
        static::assertSame('keys.example', $sector->host);
    }

    /**
     * CIBA Core §4, RFC 8628 §3.4
     *
     * @param list<GrantTypeName> $grantTypes
     */
    #[Test]
    #[DataProvider('provideGrantsWithoutARedirection')]
    public function aClientAGrantReachesWithoutARedirectionNamesNoSectorByItsRedirection(array $grantTypes): void
    {
        // Given
        $registration = self::reachedWithoutARedirection($grantTypes, Methods::clientSecretBasic())->registration;

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers nothing that says which sector its subject identifiers belong to');

        // When
        Sectors::ofAProvider()->sectorOf($registration);
    }

    /**
     * @return iterable<string, array{list<GrantTypeName>}>
     */
    public static function provideGrantsWithoutARedirection(): iterable
    {
        yield 'the device grant' => [[Grants::authorizationCode(), Grants::deviceCode()]];
        yield 'the backchannel flow' => [[Grants::authorizationCode(), Grants::ciba()]];
    }

    /**
     * OIDC Core §4, §8.1
     */
    #[Test]
    public function aClientWhoseLoginUriIsOnAnotherHostThanItsRedirectionNamesNoSectorWithoutADocument(): void
    {
        // Given
        $registration = Clients::withThirdPartyInitiatedLogin(
            Fixtures::tenant(),
            initiateLoginUri: 'https://elsewhere.example/start',
            subjectType: PairwiseSubjectIdentifierResolver::SUBJECT_TYPE,
        )->registration;

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers redirection and login URIs on rp.example and elsewhere.example');

        // When
        Sectors::ofAProvider()->sectorOf($registration);
    }

    /**
     * OIDC Core §4, §8.1
     */
    #[Test]
    public function aClientWhoseLoginUriIsOnTheHostOfItsRedirectionIsOfThatHost(): void
    {
        // Given
        $registration = Clients::withThirdPartyInitiatedLogin(Fixtures::tenant(), subjectType: PairwiseSubjectIdentifierResolver::SUBJECT_TYPE)->registration;

        // When
        $sector = Sectors::ofAProvider()->sectorOf($registration);

        // Then
        static::assertSame('rp.example', $sector->host);
    }

    #[Test]
    public function aWayOfSayingItThatNobodyWiredReadsNothing(): void
    {
        // Given
        $registration = self::backchannel(Fixtures::tenant(), jwksUri: 'https://terminal.example/jwks.json')->registration;
        $withoutTheBackchannelSource = new SectorIdentifiers([new RedirectUriSectorIdentifier(Sectors::withoutARedirection())]);

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

    /**
     * OIDC Core §4, OIDC Registration §5
     */
    #[Test]
    public function aClientPublishesItsLoginUriBesideItsRedirectionUris(): void
    {
        // Given
        $registration = Clients::withThirdPartyInitiatedLogin(Fixtures::tenant())->registration;

        // When
        $published = Sectors::ofAProvider()->publishedUris($registration);

        // Then
        static::assertSame(['https://rp.example/callback', 'https://rp.example/start'], $published);
    }

    /**
     * CIBA Core §4, RFC 8628 §3.4
     */
    #[Test]
    public function aClientTheDeviceGrantReachesPublishesItsKeysAndNotItsRedirection(): void
    {
        // Given
        $registration = self::reachedWithoutARedirection(
            [Grants::authorizationCode(), Grants::deviceCode()],
            Methods::privateKeyJwt(),
            'https://keys.example/jwks.json',
        )->registration;

        // When
        $published = Sectors::ofAProvider()->publishedUris($registration);

        // Then
        static::assertSame(['https://keys.example/jwks.json'], $published);
    }

    /**
     * CIBA Core §4
     */
    #[Test]
    public function aClientThatAuthenticatesWithASecretPublishesNothingOfItsKeys(): void
    {
        // Given
        $registration = self::backchannel(
            Fixtures::tenant(),
            jwksUri: 'https://terminal.example/jwks.json',
            sectorIdentifierUri: 'https://sector.example/redirect_uris.json',
            method: Methods::clientSecretBasic(),
        )->registration;

        // When
        $published = Sectors::ofAProvider()->publishedUris($registration);

        // Then
        static::assertSame([], $published);
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

    /**
     * @param list<GrantTypeName>|null $grantTypes
     * @param list<RedirectUri> $redirectUris
     */
    private static function backchannel(
        Tenant $tenant,
        string $clientId = 'payment-terminal',
        ?string $jwksUri = null,
        ?string $sectorIdentifierUri = null,
        ?ClientAuthenticationMethodInterface $method = null,
        ?array $grantTypes = null,
        array $redirectUris = [],
    ): Client {
        return Clients::backchannel(
            $tenant,
            new FakePasswordHasher()->hash(self::SECRET_HASH_SOURCE),
            $clientId,
            grantTypes: $grantTypes,
            jwksUri: $jwksUri,
            sectorIdentifierUri: $sectorIdentifierUri,
            method: $method ?? ($jwksUri === null ? null : Methods::privateKeyJwt()),
            redirectUris: $redirectUris,
        );
    }

    /**
     * @param list<GrantTypeName> $grantTypes
     */
    private static function reachedWithoutARedirection(array $grantTypes, ClientAuthenticationMethodInterface $method, ?string $jwksUri = null): Client
    {
        return self::backchannel(
            Fixtures::tenant(),
            'reached-without-a-redirection',
            $jwksUri,
            method: $method,
            grantTypes: $grantTypes,
            redirectUris: [new RedirectUri('https://rp.example/callback')],
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
