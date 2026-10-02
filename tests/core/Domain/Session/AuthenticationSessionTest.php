<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Session;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\AuthenticationContextClass;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Beffroi\Core\Domain\Session\AuthenticationProofs;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\LogicException;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class AuthenticationSessionTest extends TestCase
{
    #[Test]
    public function aNewSessionIsActive(): void
    {
        // When
        $session = Fixtures::session();

        // Then
        static::assertTrue($session->isActive(Fixtures::now()));
        static::assertFalse($session->hasEnded());
    }

    #[Test]
    public function aNewSessionWasLastSeenWhereAndWhenItWasCreated(): void
    {
        // When
        $session = Fixtures::session();

        // Then
        static::assertSame($session->createdFrom, $session->lastSeenFrom);
        static::assertSame($session->establishedAt, $session->lastSeenAt);
    }

    #[Test]
    public function aNewSessionIsAuthenticatedWhenItWasEstablished(): void
    {
        // When
        $session = Fixtures::session();

        // Then
        static::assertEquals($session->establishedAt, $session->authenticatedAt());
        static::assertSame(['pwd'], $session->methodReferences());
    }

    /**
     * OIDC Core §2 "acr", architecture §3.2: read from the proofs, "1" for the one factor a password is.
     */
    #[Test]
    public function aSessionEstablishedByAPasswordSatisfiesTheSingleFactorClass(): void
    {
        // When
        $session = Fixtures::session();

        // Then
        static::assertTrue($session->authenticationContextClass()->equals(AuthenticationContextClass::singleFactor()));
        static::assertSame('1', $session->authenticationContextClass()->value);
    }

    /**
     * OIDC Core §5.5.1.1: a session satisfies a requested class when its proofs meet it, a class below
     * the strongest included.
     */
    #[Test]
    public function aSessionSatisfiesTheClassesItsProofsMeet(): void
    {
        // Given
        $user = Fixtures::user();
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())->with(
            new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD),
            Fixtures::now(),
        );
        $session = new AuthenticationSession(
            Uuid::v7(),
            $user->tenant,
            $user,
            Fixtures::now(),
            $proofs,
            Fixtures::context(),
            Fixtures::now()->modify('+1 hour'),
        );

        // When / Then
        static::assertTrue($session->satisfies(AuthenticationContextClass::singleFactor()));
        static::assertTrue($session->satisfies(AuthenticationContextClass::twoFactors()));
        static::assertFalse($session->satisfies(AuthenticationContextClass::phishingResistant()));
    }

    /**
     * Architecture §3.2: a step-up adds a proof, and the class moves with it as auth_time does.
     */
    #[Test]
    public function aNewProofOfAnotherKindRaisesTheClass(): void
    {
        // Given
        $session = Fixtures::session();

        // When
        $session->recordProof(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::context(Fixtures::now()->modify('+5 minutes')));

        // Then
        static::assertSame('2', $session->authenticationContextClass()->value);
    }

    #[Test]
    public function itRecordsEveryMethodProven(): void
    {
        // Given
        $user = Fixtures::user();
        $proofs = AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now())->with(
            new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD),
            Fixtures::now(),
        );

        // When
        $session = new AuthenticationSession(
            Uuid::v7(),
            $user->tenant,
            $user,
            Fixtures::now(),
            $proofs,
            Fixtures::context(),
            Fixtures::now()->modify('+1 hour'),
        );

        // Then
        static::assertSame(['pwd', 'otp', 'mfa'], $session->methodReferences());
    }

    #[Test]
    public function itExpiresAfterItWasEstablished(): void
    {
        // Given
        $user = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new AuthenticationSession(
            Uuid::v7(),
            $user->tenant,
            $user,
            Fixtures::now(),
            AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now()),
            Fixtures::context(),
            Fixtures::now(),
        );
    }

    #[Test]
    public function itsFirstProofsAreNotDatedAfterItWasEstablished(): void
    {
        // Given
        $user = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new AuthenticationSession(
            Uuid::v7(),
            $user->tenant,
            $user,
            Fixtures::now(),
            AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now()->modify('+1 second')),
            Fixtures::context(),
            Fixtures::now()->modify('+1 hour'),
        );
    }

    #[Test]
    public function itAuthenticatesAUserOfItsOwnTenant(): void
    {
        // Given
        $user = Fixtures::user();

        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new AuthenticationSession(
            Uuid::v7(),
            Fixtures::tenant('other', 'https://id.other.example'),
            $user,
            Fixtures::now(),
            AuthenticationProofs::of(AuthenticationMethod::password(), Fixtures::now()),
            Fixtures::context(),
            Fixtures::now()->modify('+1 hour'),
        );
    }

    /**
     * OIDC Core §2: auth_time is the time of the End-User authentication; a re-authentication moves it.
     */
    #[Test]
    public function aNewProofMovesAuthTime(): void
    {
        // Given
        $session = Fixtures::session();
        $later = Fixtures::now()->modify('+2 hours');

        // When
        $session->recordProof(new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY), Fixtures::context($later, '198.51.100.7'));

        // Then
        static::assertEquals($later, $session->authenticatedAt());
        static::assertEquals(Fixtures::now(), $session->establishedAt);
    }

    /**
     * The proofs of other methods keep their own date (symfony/symfony#66064).
     */
    #[Test]
    public function aNewProofKeepsTheOtherProofs(): void
    {
        // Given
        $session = Fixtures::session();

        // When
        $session->recordProof(
            new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY),
            Fixtures::context(Fixtures::now()->modify('+2 hours'), '198.51.100.7'),
        );

        // Then
        static::assertSame(['pwd', 'hwk', 'mfa'], $session->methodReferences());
        static::assertEquals(Fixtures::now(), $session->proofs->provenAt(AuthenticationMethod::password()));
    }

    #[Test]
    public function aNewProofRecordsWhereAndWhenTheSessionWasLastSeen(): void
    {
        // Given
        $session = Fixtures::session();
        $later = Fixtures::now()->modify('+2 hours');
        $context = Fixtures::context($later, '198.51.100.7');

        // When
        $session->recordProof(new AuthenticationMethod(AuthenticationMethod::HARDWARE_KEY), $context);

        // Then
        static::assertSame($context, $session->lastSeenFrom);
        static::assertSame($later, $session->lastSeenAt);
    }

    #[Test]
    public function aProofAtTheVeryInstantTheSessionWasEstablishedIsAccepted(): void
    {
        // Given
        $session = Fixtures::session();

        // When
        $session->recordProof(new AuthenticationMethod(AuthenticationMethod::ONE_TIME_PASSWORD), Fixtures::context(Fixtures::now()));

        // Then
        static::assertSame(['pwd', 'otp', 'mfa'], $session->methodReferences());
    }

    #[Test]
    public function aProofCannotPredateTheSession(): void
    {
        // Given
        $session = Fixtures::session();

        // Then
        $this->expectException(LogicException::class);

        // When
        $session->recordProof(AuthenticationMethod::password(), Fixtures::context(Fixtures::now()->modify('-1 minute')));
    }

    #[Test]
    public function anEndedSessionCannotReceiveAProof(): void
    {
        // Given
        $session = Fixtures::session();
        $session->end(SessionEnd::User, Fixtures::now());

        // Then
        $this->expectException(LogicException::class);

        // When
        $session->recordProof(AuthenticationMethod::password(), Fixtures::context(Fixtures::now()->modify('+1 minute')));
    }

    #[Test]
    public function touchingRecordsWhereAndWhenTheSessionWasSeenAndExtendsIt(): void
    {
        // Given
        $session = Fixtures::session();
        $later = Fixtures::now()->modify('+2 hours');
        $context = Fixtures::context($later, '198.51.100.7');

        // When
        $session->touch($context, $later->modify('+12 hours'));

        // Then
        static::assertSame($context, $session->lastSeenFrom);
        static::assertSame($later, $session->lastSeenAt);
        static::assertEquals($later->modify('+12 hours'), $session->expiresAt);
    }

    #[Test]
    public function touchingMayKeepTheSameExpiry(): void
    {
        // Given
        $session = Fixtures::session();
        $expiresAt = $session->expiresAt;

        // When
        $session->touch(Fixtures::context(Fixtures::now()->modify('+2 hours')), $expiresAt);

        // Then
        static::assertSame($expiresAt, $session->expiresAt);
    }

    #[Test]
    public function touchingNeverShortensTheSession(): void
    {
        // Given
        $session = Fixtures::session();
        $later = Fixtures::now()->modify('+2 hours');

        // Then
        $this->expectException(LogicException::class);

        // When
        $session->touch(Fixtures::context($later), $later);
    }

    #[Test]
    public function itIsActiveUntilItExpires(): void
    {
        // Given
        $session = Fixtures::session();

        // When / Then
        static::assertTrue($session->isActive(Fixtures::now()->modify('+11 hours')));
    }

    #[Test]
    public function itIsInactiveOnceExpiredWithoutHavingEnded(): void
    {
        // Given
        $session = Fixtures::session();

        // When / Then
        static::assertFalse($session->isActive(Fixtures::now()->modify('+12 hours')));
        static::assertFalse($session->hasEnded());
    }

    #[Test]
    public function endingMakesTheSessionInactive(): void
    {
        // Given
        $session = Fixtures::session();
        $endedAt = new DateTimeImmutable('2026-09-15T11:00:00+00:00');

        // When
        $session->end(SessionEnd::User, $endedAt);

        // Then
        static::assertTrue($session->hasEnded());
        static::assertFalse($session->isActive($endedAt));
        static::assertSame($endedAt, $session->endedAt);
        static::assertSame(SessionEnd::User, $session->endedBy);
    }

    #[Test]
    public function theFirstEndWins(): void
    {
        // Given
        $session = Fixtures::session();
        $first = new DateTimeImmutable('2026-09-15T11:00:00+00:00');
        $session->end(SessionEnd::User, $first);

        // When
        $session->end(SessionEnd::Expiry, new DateTimeImmutable('2026-09-15T12:00:00+00:00'));

        // Then
        static::assertSame($first, $session->endedAt);
        static::assertSame(SessionEnd::User, $session->endedBy);
    }

    #[Test]
    public function anEndedSessionCannotBeTouched(): void
    {
        // Given
        $session = Fixtures::session();
        $session->end(SessionEnd::Administrator, Fixtures::now());

        // Then
        $this->expectException(LogicException::class);

        // When
        $session->touch(Fixtures::context(), Fixtures::now()->modify('+1 day'));
    }
}
