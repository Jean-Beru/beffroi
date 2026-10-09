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

/**
 * Issue #473: where a session was opened and where it was last seen, written after the request that
 * wrote the row.
 */
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

    /**
     * The enrichment adds a place and rewrites nothing: what a request carried is what reached this
     * provider.
     */
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

    /**
     * Both provenances of a new session carry the one address the login came from: a second lookup would
     * read a database for an answer already in hand.
     */
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

    /**
     * A step-up records the address it came from, which is not the one the session was opened from: both
     * are looked up, and each provenance says its own place.
     */
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

    /**
     * The row is written, which is the point of all of it: the session a request wrote says a place it did
     * not say when the request ended.
     */
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

    /**
     * One provenance located and the other not, which is a step-up from a network no database covers: the
     * place that was found is written and the one that was not is not invented.
     */
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

    /**
     * A deployment that holds no database writes nothing at all: the row would not change, and a row that
     * would not change is a row this never touches.
     */
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

    /**
     * The message arrives on a lane, where a session may have been forgotten since. That is late, not
     * wrong, and nothing of it fails.
     */
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
