<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Enrolment;

use Beffroi\Core\Application\Authentication\DecoyHash;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Application\Enrolment\EnrolmentTicketRedemption;
use Beffroi\Core\Application\Ticket\TicketIssuing;
use Beffroi\Core\Application\Ticket\TicketRedeeming;
use Beffroi\Core\Bridge\InMemory\InMemoryEnrolmentTicketRepository;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Domain\Ticket\IssuedTicket;
use Beffroi\Core\Exception\TicketRefusedException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingCredentialChangeNotifier;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Uid\Uuid;

final class EnrolmentTicketRedemptionTest extends TestCase
{
    private const string REFUSED = 'This ticket opens nothing.';

    private Tenant $tenant;

    private User $alice;

    private InMemoryEnrolmentTicketRepository $tickets;

    private FakePasswordHasher $hasher;

    private MockClock $clock;

    private EnrolmentTicketRedemption $redemption;

    /**
     * @var IssuedTicket<EnrolmentTicket>
     */
    private IssuedTicket $issued;

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->tickets = new InMemoryEnrolmentTicketRepository();
        $this->hasher = new FakePasswordHasher();
        $this->clock = new MockClock('2026-10-11T12:00:00+00:00');
        $this->issued = new EnrolmentTicketIssue(
            $this->tickets,
            new TicketIssuing(new SymfonyUuidGenerator(), new PlatformRandomness(), $this->hasher, $this->clock),
            new RecordingEventDispatcher(),
            new RecordingCredentialChangeNotifier(),
        )->issue($this->alice, Fixtures::context($this->clock->now()));
        $this->redemption = new EnrolmentTicketRedemption(
            $this->tickets,
            new TicketRedeeming($this->hasher, new DecoyHash($this->hasher, new SymfonyUuidGenerator()), $this->clock),
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
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->redemption->redeem($this->tenant, Uuid::v7(), $this->issued->value);
    }

    /**
     * Decision 0006
     */
    #[Test]
    public function anIdentifierNothingAnswersPaysForAHashAllTheSame(): void
    {
        // When
        try {
            $this->redemption->redeem($this->tenant, Uuid::v7(), $this->issued->value);
        } catch (TicketRefusedException) {
        }

        // Then
        static::assertCount(1, $this->hasher->verifiedAgainst);
        static::assertNotSame($this->issued->ticket->secret->encoded, $this->hasher->verifiedAgainst[0]);
    }

    #[Test]
    public function aWrongValueOpensNothing(): void
    {
        // Then
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->redemption->redeem($this->tenant, $this->issued->ticket->id, 'not the value of the link');
    }

    #[Test]
    public function aTicketOfAnotherTenantOpensNothing(): void
    {
        // Then
        $this->expectException(TicketRefusedException::class);
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
        $this->expectException(TicketRefusedException::class);
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
        $this->expectException(TicketRefusedException::class);
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
        $this->expectException(TicketRefusedException::class);
        $this->expectExceptionMessageIs(self::REFUSED);

        // When
        $this->redemption->redeem($this->tenant, $this->issued->ticket->id, $this->issued->value);
    }

    #[Test]
    public function aTicketSpentCostsWhatAWrongValueCosts(): void
    {
        // Given
        $this->redemption->spend($this->issued->ticket);

        // When
        try {
            $this->redemption->redeem($this->tenant, $this->issued->ticket->id, $this->issued->value);
        } catch (TicketRefusedException) {
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
