<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Session;

use DateTimeImmutable;
use Heidi\Core\Domain\Session\AuthenticationMethod;
use Heidi\Core\Domain\Session\AuthenticationProofs;
use Heidi\Core\Domain\Session\AuthenticationSession;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Exception\InvalidArgumentException;
use Heidi\Core\Exception\LogicException;
use Heidi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class AuthenticationSessionTest extends TestCase
{
    #[Test]
    public function aNewSessionIsActiveAndWasLastSeenWhereItWasCreated(): void
    {
        $session = Fixtures::session();

        static::assertTrue($session->isActive(Fixtures::now()));
        static::assertFalse($session->hasEnded());
        static::assertSame($session->createdFrom, $session->lastSeenFrom);
        static::assertSame($session->establishedAt, $session->lastSeenAt);
        static::assertEquals($session->establishedAt, $session->authenticatedAt());
        static::assertSame(['pwd'], $session->methodReferences());
        static::assertNull($session->authenticationContextClass);
    }

    #[Test]
    public function itCarriesAnAcrWhenTheDeploymentDefinesOne(): void
    {
        $user = Fixtures::user();
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())->with(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::now());
        $session = new AuthenticationSession(Uuid::v7(), $user->tenant, $user, Fixtures::now(), $proofs, 'urn:acme:loa:2', Fixtures::context(), Fixtures::now()->modify('+1 hour'));

        static::assertSame(['pwd', 'otp'], $session->methodReferences());
        static::assertSame('urn:acme:loa:2', $session->authenticationContextClass);
    }

    #[Test]
    public function anEmptyAcrIsNotAnAcr(): void
    {
        $user = Fixtures::user();

        $this->expectException(InvalidArgumentException::class);
        new AuthenticationSession(Uuid::v7(), $user->tenant, $user, Fixtures::now(), AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now()), '', Fixtures::context(), Fixtures::now()->modify('+1 hour'));
    }

    #[Test]
    public function itExpiresAfterItWasEstablished(): void
    {
        $user = Fixtures::user();

        $this->expectException(InvalidArgumentException::class);
        new AuthenticationSession(Uuid::v7(), $user->tenant, $user, Fixtures::now(), AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now()), null, Fixtures::context(), Fixtures::now());
    }

    #[Test]
    public function itsFirstProofsAreNotDatedAfterItWasEstablished(): void
    {
        $user = Fixtures::user();

        $this->expectException(InvalidArgumentException::class);
        new AuthenticationSession(Uuid::v7(), $user->tenant, $user, Fixtures::now(), AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now()->modify('+1 second')), null, Fixtures::context(), Fixtures::now()->modify('+1 hour'));
    }

    #[Test]
    public function itAuthenticatesAUserOfItsOwnTenant(): void
    {
        $user = Fixtures::user();

        $this->expectException(InvalidArgumentException::class);
        new AuthenticationSession(Uuid::v7(), Fixtures::tenant('other', 'https://id.other.example'), $user, Fixtures::now(), AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now()), null, Fixtures::context(), Fixtures::now()->modify('+1 hour'));
    }

    /**
     * OIDC Core §2: auth_time is the time of the End-User authentication; a re-authentication moves it, and
     * the proofs of other methods keep their own date (symfony/symfony#66064).
     */
    #[Test]
    public function aNewProofMovesAuthTimeAndKeepsTheOtherProofs(): void
    {
        $session = Fixtures::session();
        $later = Fixtures::now()->modify('+2 hours');
        $context = Fixtures::context($later, '198.51.100.7');

        $session->recordProof(new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY), $context);

        static::assertEquals($later, $session->authenticatedAt());
        static::assertSame(['pwd', 'hwk'], $session->methodReferences());
        static::assertEquals(Fixtures::now(), $session->proofs->provenAt(AuthenticationMethod::password()));
        static::assertSame($context, $session->lastSeenFrom);
        static::assertSame($later, $session->lastSeenAt);
        static::assertEquals(Fixtures::now(), $session->establishedAt);
    }

    #[Test]
    public function aProofAtTheVeryInstantTheSessionWasEstablishedIsAccepted(): void
    {
        $session = Fixtures::session();

        $session->recordProof(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::context(Fixtures::now()));

        static::assertSame(['pwd', 'otp'], $session->methodReferences());
    }

    #[Test]
    public function aProofCannotPredateTheSession(): void
    {
        $session = Fixtures::session();

        $this->expectException(LogicException::class);
        $session->recordProof(AuthenticationMethod::password(), Fixtures::context(Fixtures::now()->modify('-1 minute')));
    }

    #[Test]
    public function anEndedSessionCannotReceiveAProof(): void
    {
        $session = Fixtures::session();
        $session->end(SessionEnd::User, Fixtures::now());

        $this->expectException(LogicException::class);
        $session->recordProof(AuthenticationMethod::password(), Fixtures::context(Fixtures::now()->modify('+1 minute')));
    }

    #[Test]
    public function touchingRecordsWhereAndWhenAndMayExtendButNeverShorten(): void
    {
        $session = Fixtures::session();
        $later = Fixtures::now()->modify('+2 hours');
        $context = Fixtures::context($later, '198.51.100.7');

        $session->touch($context, $later->modify('+12 hours'));
        static::assertSame($context, $session->lastSeenFrom);
        static::assertSame($later, $session->lastSeenAt);
        static::assertEquals($later->modify('+12 hours'), $session->expiresAt);

        $session->touch($context, $later->modify('+12 hours'));

        $this->expectException(LogicException::class);
        $session->touch($context, $later);
    }

    #[Test]
    public function itIsInactiveOnceExpired(): void
    {
        $session = Fixtures::session();

        static::assertTrue($session->isActive(Fixtures::now()->modify('+11 hours')));
        static::assertFalse($session->isActive(Fixtures::now()->modify('+12 hours')));
        static::assertFalse($session->hasEnded());
    }

    #[Test]
    public function theFirstEndWins(): void
    {
        $session = Fixtures::session();
        $t1 = new DateTimeImmutable('2026-09-15T11:00:00+00:00');
        $t2 = new DateTimeImmutable('2026-09-15T12:00:00+00:00');

        $session->end(SessionEnd::User, $t1);
        $session->end(SessionEnd::Expiry, $t2);

        static::assertTrue($session->hasEnded());
        static::assertFalse($session->isActive($t1));
        static::assertSame($t1, $session->endedAt);
        static::assertSame(SessionEnd::User, $session->endedBy);
    }

    #[Test]
    public function anEndedSessionCannotBeTouched(): void
    {
        $session = Fixtures::session();
        $session->end(SessionEnd::Administrator, Fixtures::now());

        $this->expectException(LogicException::class);
        $session->touch(Fixtures::context(), Fixtures::now()->modify('+1 day'));
    }
}
