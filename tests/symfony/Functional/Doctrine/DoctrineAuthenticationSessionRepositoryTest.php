<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_map;
use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\Device;
use Heidi\Core\Domain\Session\DeviceType;
use Heidi\Core\Domain\Session\GeoLocation;
use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §3.2, §3.5: a session with its proofs and the provenance of its first and last request;
 * the active sessions of a user are those that neither ended nor expired.
 */
final class DoctrineAuthenticationSessionRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aSessionComesBackWithItsUserItsProofsAndItsAcr(): void
    {
        // Given
        $user = self::user();
        $establishedAt = self::now();
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), $establishedAt->modify('-1 minute'))
            ->with(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), $establishedAt);
        $session = new AuthenticationSession(Uuid::v7(), $user->tenant, $user, $establishedAt, $proofs, self::enrichedContext($establishedAt), $establishedAt->modify('+12 hours'));
        self::sessions()->save($session);
        self::reload();

        // When
        $found = self::sessions()->find($session->id) ?? static::fail('The session was not stored.');

        // Then
        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertEquals($establishedAt, $found->establishedAt);
        static::assertEquals($proofs, $found->proofs);
        static::assertSame(['pwd', 'otp'], $found->methodReferences());
        static::assertEquals($establishedAt, $found->authenticatedAt());
        static::assertEquals($establishedAt->modify('+12 hours'), $found->expiresAt);
        static::assertNull($found->endedAt);
        static::assertNull($found->endedBy);
        static::assertTrue($found->isActive($establishedAt->modify('+2 hours')));
    }

    /**
     * Architecture §3.5: the provenance of the session, enriched, comes back whole.
     */
    #[Test]
    public function aSessionComesBackWithItsEnrichedProvenance(): void
    {
        // Given
        $user = self::user();
        $establishedAt = self::now();
        $createdFrom = self::enrichedContext($establishedAt);
        $session = new AuthenticationSession(Uuid::v7(), $user->tenant, $user, $establishedAt, AuthenticationProofs::of(AuthenticationMethod::password(), $establishedAt), $createdFrom, $establishedAt->modify('+12 hours'));
        self::sessions()->save($session);
        self::reload();

        // When
        $found = self::sessions()->find($session->id) ?? static::fail('The session was not stored.');

        // Then
        static::assertEquals($createdFrom, $found->createdFrom);
        static::assertTrue($found->createdFrom->isEnriched());
    }

    /**
     * A touch is written on save: where and when the session was last seen, and its new expiry.
     */
    #[Test]
    public function aTouchIsWrittenOnSave(): void
    {
        // Given
        $establishedAt = self::now();
        $session = self::session(self::user(), $establishedAt);
        $session->touch(new RequestContext($establishedAt->modify('+1 hour'), '2001:db8::1', 'curl/8.0'), $establishedAt->modify('+13 hours'));
        self::sessions()->save($session);
        self::reload();

        // When
        $found = self::sessions()->find($session->id) ?? static::fail('The session was not stored.');

        // Then
        static::assertSame('2001:db8::1', $found->lastSeenFrom->ipAddress);
        static::assertSame('curl/8.0', $found->lastSeenFrom->userAgent);
        static::assertNull($found->lastSeenFrom->location);
        static::assertNull($found->lastSeenFrom->device);
        static::assertFalse($found->lastSeenFrom->isEnriched());
        static::assertEquals($establishedAt->modify('+1 hour'), $found->lastSeenAt);
        static::assertEquals($establishedAt->modify('+13 hours'), $found->expiresAt);
    }

    #[Test]
    public function anEndIsWrittenOnSave(): void
    {
        // Given
        $session = self::session(self::user());
        $session->end(SessionEnd::RelyingParty, self::now()->modify('+1 hour'));
        self::sessions()->save($session);
        self::reload();

        // When
        $found = self::sessions()->find($session->id) ?? static::fail('The session was not stored.');

        // Then
        static::assertEquals(self::now()->modify('+1 hour'), $found->endedAt);
        static::assertSame(SessionEnd::RelyingParty, $found->endedBy);
        static::assertTrue($found->hasEnded());
    }

    /**
     * The list a user sees when reviewing where they are logged in: ended and expired sessions are not
     * in it, nor the sessions of somebody else.
     */
    #[Test]
    public function theActiveSessionsOfAUserAreThoseNeitherEndedNorExpired(): void
    {
        // Given
        $alice = self::user();
        $first = self::session($alice, self::now()->modify('-2 hours'));
        $ended = self::session($alice, self::now()->modify('-1 hour'));
        $ended->end(SessionEnd::User, self::now());
        self::sessions()->save($ended);
        self::session($alice, self::now()->modify('-13 hours'));
        $second = self::session($alice, self::now());
        self::session(self::user('bob', 'bob-subject'));
        self::reload();

        // When
        $active = self::sessions()->findActiveByUser($alice, self::now()->modify('+1 minute'));

        // Then
        static::assertSame([$first->id->toRfc4122(), $second->id->toRfc4122()], array_map(static fn (AuthenticationSession $session): string => $session->id->toRfc4122(), $active));
    }

    #[Test]
    public function aUserHasNoActiveSessionOnceTheyAllExpired(): void
    {
        // Given
        $alice = self::user();
        self::session($alice, self::now());
        self::reload();

        // When
        $active = self::sessions()->findActiveByUser($alice, self::now()->modify('+13 hours'));

        // Then
        static::assertSame([], $active);
    }

    #[Test]
    public function anUnknownIdentifierFindsNoSession(): void
    {
        // When / Then
        static::assertNull(self::sessions()->find(Uuid::v7()));
    }

    private static function sessions(): AuthenticationSessionRepositoryInterface
    {
        return self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class);
    }

    /**
     * A request context with a location and a device, as the enrichment will produce it.
     */
    private static function enrichedContext(DateTimeImmutable $receivedAt): RequestContext
    {
        return new RequestContext($receivedAt, '203.0.113.10', 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0', new GeoLocation('FR', 'Île-de-France', 'Paris', 3215, 'Orange S.A.', 48.8566, 2.3522), new Device(DeviceType::Desktop, 'Firefox', '140.0', 'Linux'));
    }
}
