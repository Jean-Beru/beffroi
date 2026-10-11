<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Enrolment;

use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketRedemption;
use Beffroi\Core\Bridge\InMemory\InMemoryEnrolmentTicketRepository;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Enrolment\IssuedEnrolmentTicket;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\EnrolmentTicketRefusedException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #613: what a ticket presented opens, and the whole order of reading it. Every refusal is the same
 * sentence and costs one hash, so neither the answer nor the time says which of the reasons it was.
 */
final class EnrolmentTicketRedemptionTest extends TestCase
{
    private const string REFUSED = 'This enrolment ticket opens nothing.';

    private Tenant $tenant;

    private User $alice;

    private InMemoryEnrolmentTicketRepository $tickets;

    private FakePasswordHasher $hasher;

    private MockClock $clock;

    private EnrolmentTicketRedemption $redemption;

    private IssuedEnrolmentTicket $issued;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->tickets = new InMemoryEnrolmentTicketRepository();
        $this->hasher = new FakePasswordHasher();
        $this->clock = new MockClock('2026-10-11T12:00:00+00:00');
        $this->issued = new EnrolmentTicketIssue(
            $this->tickets,
            new SymfonyUuidGenerator(),
            new PlatformRandomness(),
            $this->hasher,
            $this->clock,
            new RecordingEventDispatcher(),
        )->issue($this->alice, Fixtures::context($this->clock->now()));
        $this->redemption = new EnrolmentTicketRedemption(
            $this->tickets,
            $this->hasher,
            new DecoyHash($this->hasher, new SymfonyUuidGenerator()),
            $this->clock,
        );
    }

    #[Test]
    public function theTicketOfTheLinkOpensItsEnrolment(): void
    {
        // When
        $ticket = $this->redemption->redeem($this->tenant, $this->issued->ticket->id, $this->issued->value);

        // Then
        static::assertSame($this->issued->ticket, $ticket);
    }

    #[Test]
    public function anIdentifierNothingAnswersOpensNothing(): void
    {
        // Then
        $this->expectException(EnrolmentTicketRefusedException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->redemption->redeem($this->tenant, Uuid::v7(), $this->issued->value);
    }

    /**
     * Decision 0006: a refusal reached before the hash of a ticket could be verified pays for one
     * (`DecoyHash`), so the time does not say whether a ticket of that identifier exists.
     */
    #[Test]
    public function anIdentifierNothingAnswersPaysForAHashAllTheSame(): void
    {
        // When
        try {
            $this->redemption->redeem($this->tenant, Uuid::v7(), $this->issued->value);
        } catch (EnrolmentTicketRefusedException) {
            // the refusal is read by the test above
        }

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
        static::assertNotSame($this->issued->ticket->secret->encoded, $this->hasher->verifiedAgainst[0]);
    }

    #[Test]
    public function aWrongValueOpensNothing(): void
    {
        // Then
        $this->expectException(EnrolmentTicketRefusedException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->redemption->redeem($this->tenant, $this->issued->ticket->id, 'not the value of the link');
    }

    #[Test]
    public function aTicketOfAnotherTenantOpensNothing(): void
    {
        // Then
        $this->expectException(EnrolmentTicketRefusedException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->redemption->redeem(
            Fixtures::tenant('other', 'https://id.other.example'),
            $this->issued->ticket->id,
            $this->issued->value,
        );
    }

    #[Test]
    public function aTicketSpentOpensNothingASecondTime(): void
    {
        // Given
        $this->redemption->spend($this->issued->ticket);

        // Then
        $this->expectException(EnrolmentTicketRefusedException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->redemption->redeem($this->tenant, $this->issued->ticket->id, $this->issued->value);
    }

    #[Test]
    public function aTicketOutOfTimeOpensNothing(): void
    {
        // Given
        $this->clock->modify('+72 hours');

        // Then
        $this->expectException(EnrolmentTicketRefusedException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->redemption->redeem($this->tenant, $this->issued->ticket->id, $this->issued->value);
    }

    #[Test]
    public function aTicketOfAPersonWhoCannotSignInOpensNothing(): void
    {
        // Given
        $this->alice->disable($this->clock->now());

        // Then
        $this->expectException(EnrolmentTicketRefusedException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->redemption->redeem($this->tenant, $this->issued->ticket->id, $this->issued->value);
    }

    /**
     * The state of the ticket is read after the value on purpose: a ticket already spent answers like a
     * wrong value, and costs the same.
     */
    #[Test]
    public function aTicketSpentCostsWhatAWrongValueCosts(): void
    {
        // Given
        $this->redemption->spend($this->issued->ticket);

        // When
        try {
            $this->redemption->redeem($this->tenant, $this->issued->ticket->id, $this->issued->value);
        } catch (EnrolmentTicketRefusedException) {
            // the refusal is read by the test above
        }

        // Then
        static::assertSame([$this->issued->ticket->secret->encoded], $this->hasher->verifiedAgainst);
    }

    #[Test]
    public function aSpentTicketIsSaidToBeSpentAndSaved(): void
    {
        // When
        $this->redemption->spend($this->issued->ticket);

        // Then
        static::assertEquals($this->clock->now(), $this->issued->ticket->spentAt);
        static::assertSame([], $this->tickets->unspentOf($this->alice));
    }
}
