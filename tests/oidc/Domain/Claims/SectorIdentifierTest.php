<?php

declare(strict_types=1);

namespace Heidi\Oidc\Tests\Domain\Claims;

use Heidi\Core\Tests\Fixture\FakePasswordHasher;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Oidc\Domain\Claims\SectorIdentifier;
use Heidi\Oidc\Domain\Client\ClientRegistration;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Exception\InvalidArgumentException;
use Heidi\Oidc\Tests\Fixture\Clients;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class SectorIdentifierTest extends TestCase
{
    /**
     * OIDC Core §8.1: the host of the registered "sector_identifier_uri" when there is one, the host of the
     * redirection URIs when there is not.
     */
    #[Test]
    #[DataProvider('provideRegistrations')]
    public function itIsTheHostTheRegistrationNames(ClientRegistration $registration, string $host): void
    {
        // When
        $sector = SectorIdentifier::of($registration);

        // Then
        static::assertSame($host, $sector->host);
    }

    /**
     * @return iterable<string, array{ClientRegistration, string}>
     */
    public static function provideRegistrations(): iterable
    {
        $tenant = Fixtures::tenant();

        yield 'the host of the one redirection URI' => [
            Clients::pairwise($tenant, redirectUri: 'https://rp.example/callback')->registration,
            'rp.example',
        ];

        yield 'the host of the sector identifier document, whatever the redirection URI says' => [
            Clients::pairwise(
                $tenant,
                redirectUri: 'https://rp.example/callback',
                sectorIdentifierUri: 'https://sector.example/redirect_uris.json',
            )->registration,
            'sector.example',
        ];

        yield 'a host with a port, which is no part of a sector' => [
            Clients::pairwise($tenant, redirectUri: 'https://rp.example:8443/callback')->registration,
            'rp.example',
        ];
    }

    /**
     * Two clients of one sector see a user under one identifier: it is the sector that decides, not the
     * client, so two registrations that name the same host name the same sector.
     */
    #[Test]
    public function twoClientsOfTheSameHostShareOneSector(): void
    {
        // Given
        $tenant = Fixtures::tenant();

        // When
        $one = SectorIdentifier::of(Clients::pairwise($tenant, 'one', 'https://rp.example/one')->registration);
        $other = SectorIdentifier::of(Clients::pairwise($tenant, 'other', 'https://rp.example/other')->registration);

        // Then
        static::assertTrue($one->equals($other));
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
        $registration = Clients::pairwise(Fixtures::tenant(), 'two-hosts', 'https://one.example/callback')->registration;
        $onTwoHosts = new ClientRegistration(
            $registration->clientId,
            $registration->presentation,
            $registration->authenticationMethod,
            false,
            [...$registration->redirectUris, new RedirectUri('https://other.example/callback')],
            $registration->accessTokenShape,
            subjectType: $registration->subjectType,
        );

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers redirection URIs on one.example and other.example');

        // When
        SectorIdentifier::of($onTwoHosts);
    }

    /**
     * A client that registers no redirection URI at all registers nothing this reads; what answers for it is
     * its "jwks_uri" (CIBA Core §4), which is another source and another issue.
     */
    #[Test]
    public function aClientWithNoRedirectionUriNamesNoSector(): void
    {
        // Given
        $service = Clients::service(Fixtures::tenant(), new FakePasswordHasher()->hash(Clients::SECRET));

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('registers no redirection URI and no sector_identifier_uri');

        // When
        SectorIdentifier::of($service->registration);
    }

    #[Test]
    public function itRefusesAnEmptyHost(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A sector identifier is a host.');

        // When
        new SectorIdentifier('');
    }
}
