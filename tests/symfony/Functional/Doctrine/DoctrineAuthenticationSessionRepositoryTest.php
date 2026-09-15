<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Doctrine;

use function array_map;
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
    public function aSessionComesBackWithItsProofsAndItsProvenance(): void
    {
        $sessions = self::sessions();
        $user = self::user();
        $establishedAt = self::now();
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), $establishedAt->modify('-1 minute'))
            ->with(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), $establishedAt);
        $createdFrom = new RequestContext($establishedAt, '203.0.113.10', 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0', new GeoLocation('FR', 'Île-de-France', 'Paris', 3215, 'Orange S.A.', 48.8566, 2.3522), new Device(DeviceType::Desktop, 'Firefox', '140.0', 'Linux'));
        $session = new AuthenticationSession(Uuid::v7(), $user->tenant, $user, $establishedAt, $proofs, 'urn:example:acr:silver', $createdFrom, $establishedAt->modify('+12 hours'));
        $sessions->save($session);
        $session->touch(new RequestContext($establishedAt->modify('+1 hour'), '2001:db8::1', 'curl/8.0'), $establishedAt->modify('+13 hours'));
        $sessions->save($session);
        self::reload();

        $found = $sessions->find($session->id) ?? static::fail('The session was not stored.');

        static::assertTrue($found->user->id->equals($user->id));
        static::assertTrue($found->tenant->id->equals(self::tenant()->id));
        static::assertEquals($establishedAt, $found->establishedAt);
        static::assertEquals($proofs, $found->proofs);
        static::assertSame(['pwd', 'otp'], $found->methodReferences());
        static::assertEquals($establishedAt, $found->authenticatedAt());
        static::assertSame('urn:example:acr:silver', $found->authenticationContextClass);
        static::assertEquals($createdFrom, $found->createdFrom);
        static::assertTrue($found->createdFrom->isEnriched());
        static::assertSame('2001:db8::1', $found->lastSeenFrom->ipAddress);
        static::assertSame('curl/8.0', $found->lastSeenFrom->userAgent);
        static::assertNull($found->lastSeenFrom->location);
        static::assertNull($found->lastSeenFrom->device);
        static::assertFalse($found->lastSeenFrom->isEnriched());
        static::assertEquals($establishedAt->modify('+1 hour'), $found->lastSeenAt);
        static::assertEquals($establishedAt->modify('+13 hours'), $found->expiresAt);
        static::assertNull($found->endedAt);
        static::assertNull($found->endedBy);
        static::assertTrue($found->isActive($establishedAt->modify('+2 hours')));
    }

    #[Test]
    public function anEndIsWrittenOnSave(): void
    {
        $sessions = self::sessions();
        $session = self::session(self::user());
        $session->end(SessionEnd::RelyingParty, self::now()->modify('+1 hour'));
        $sessions->save($session);
        self::reload();

        $found = $sessions->find($session->id) ?? static::fail('The session was not stored.');

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
        $sessions = self::sessions();
        $alice = self::user();
        $bob = self::user('bob', 'bob-subject');
        $first = self::session($alice, self::now()->modify('-2 hours'));
        $ended = self::session($alice, self::now()->modify('-1 hour'));
        $ended->end(SessionEnd::User, self::now());
        $sessions->save($ended);
        $expired = self::session($alice, self::now()->modify('-13 hours'));
        $second = self::session($alice, self::now());
        self::session($bob);
        self::reload();

        $active = $sessions->findActiveByUser($alice, self::now()->modify('+1 minute'));

        static::assertSame([$first->id->toRfc4122(), $second->id->toRfc4122()], array_map(static fn (AuthenticationSession $session): string => $session->id->toRfc4122(), $active));
        static::assertNotContains($expired->id->toRfc4122(), array_map(static fn (AuthenticationSession $session): string => $session->id->toRfc4122(), $active));
        static::assertSame([], $sessions->findActiveByUser($alice, self::now()->modify('+13 hours')));
        static::assertNull($sessions->find(Uuid::v7()));
    }

    private static function sessions(): AuthenticationSessionRepositoryInterface
    {
        return self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class);
    }
}
