<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Session;

use Beffroi\Core\Application\Session\ProvenancePlace;
use Beffroi\Core\Application\Session\SessionProvenanceEnrichment;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Core\Bridge\Null\NullGeoLocator;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Port\GeoLocatorInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\GeoLocatorOfPlaces;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class SessionProvenanceEnrichmentTest extends TestCase
{
    private InMemoryAuthenticationSessionRepository $sessions;

    protected function setUp(): void
    {
        $this->sessions = new InMemoryAuthenticationSessionRepository();
    }

    #[Test]
    public function bothProvenancesOfASessionSayWhereTheyCameFrom(): void
    {
        // Given
        $session = $this->stored(Fixtures::session());

        // When
        $this->enrichment(new GeoLocatorOfPlaces())->enrich($session->id);

        // Then
        static::assertSame('Oxford', $session->createdFrom->location?->city);
        static::assertSame('Oxford', $session->lastSeenFrom->location?->city);
    }

    #[Test]
    public function whatTheRequestCarriedIsLeftAsItReachedTheProvider(): void
    {
        // Given
        $session = $this->stored(Fixtures::session());
        $carried = $session->createdFrom;

        // When
        $this->enrichment(new GeoLocatorOfPlaces())->enrich($session->id);

        // Then
        static::assertSame($carried->ipAddress, $session->createdFrom->ipAddress);
        static::assertSame($carried->userAgent, $session->createdFrom->userAgent);
        static::assertSame($carried->receivedAt, $session->createdFrom->receivedAt);
    }

    #[Test]
    public function oneAddressIsLookedUpOnce(): void
    {
        // Given
        $session = $this->stored(Fixtures::session());
        $locator = new GeoLocatorOfPlaces();

        // When
        $this->enrichment($locator)->enrich($session->id);

        // Then
        static::assertSame([Fixtures::IP_ADDRESS], $locator->asked);
    }

    #[Test]
    public function aSecondAddressIsLookedUpToo(): void
    {
        // Given
        $session = $this->stored(Fixtures::session());
        $session->touch(new RequestContext(Fixtures::now()->modify('+1 hour'), '198.51.100.7'), $session->expiresAt);
        $locator = new GeoLocatorOfPlaces();

        // When
        $this->enrichment($locator)->enrich($session->id);

        // Then
        static::assertSame([Fixtures::IP_ADDRESS, '198.51.100.7'], $locator->asked);
    }

    #[Test]
    public function theSessionIsWrittenBack(): void
    {
        // Given
        $session = $this->stored(Fixtures::session());
        $saves = $this->sessions->saves;

        // When
        $this->enrichment(new GeoLocatorOfPlaces())->enrich($session->id);

        // Then
        static::assertSame($saves + 1, $this->sessions->saves);
    }

    #[Test]
    public function aSessionOneOfWhoseProvenancesHasAPlaceIsWrittenAllTheSame(): void
    {
        // Given
        $session = $this->stored(Fixtures::session());
        $session->touch(new RequestContext(Fixtures::now()->modify('+1 hour'), '198.51.100.7'), $session->expiresAt);

        // When
        $this->enrichment(new GeoLocatorOfPlaces())->enrich($session->id);

        // Then
        static::assertSame('Oxford', $session->createdFrom->location?->city);
        static::assertNull($session->lastSeenFrom->location);
    }

    #[Test]
    public function aSessionNoPlaceWasFoundForIsNotWritten(): void
    {
        // Given
        $session = $this->stored(Fixtures::session());
        $saves = $this->sessions->saves;

        // When
        $this->enrichment(new NullGeoLocator())->enrich($session->id);

        // Then
        static::assertSame($saves, $this->sessions->saves);
        static::assertFalse($session->createdFrom->isEnriched());
    }

    #[Test]
    public function aSessionThatIsGoneIsNotAnError(): void
    {
        // When
        $this->enrichment(new GeoLocatorOfPlaces())->enrich(Uuid::v7());

        // Then
        static::assertSame(0, $this->sessions->saves);
    }

    private function enrichment(GeoLocatorInterface $locator): SessionProvenanceEnrichment
    {
        return new SessionProvenanceEnrichment($this->sessions, new ProvenancePlace($locator));
    }

    private function stored(AuthenticationSession $session): AuthenticationSession
    {
        $this->sessions->save($session);

        return $session;
    }
}
