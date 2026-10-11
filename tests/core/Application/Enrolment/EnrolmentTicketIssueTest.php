<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Application\Enrolment;

use Beffroi\Core\Application\Enrolment\EnrolmentTicketIssue;
use Beffroi\Core\Bridge\InMemory\InMemoryEnrolmentTicketRepository;
use Beffroi\Core\Bridge\Random\PlatformRandomness;
use Beffroi\Core\Bridge\Uid\SymfonyUuidGenerator;
use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Event\EnrolmentTicketIssued;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\EnrolmentTicketRefusedException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\RecordingEventDispatcher;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Clock\MockClock;

/**
 * Issue #613: the ticket an administrator issues so that a person with nothing to sign in with reaches
 * one enrolment. The value is drawn here and read nowhere again; the row holds its hash.
 */
final class EnrolmentTicketIssueTest extends TestCase
{
    private User $alice;

    private FakePasswordHasher $hasher;

    private InMemoryEnrolmentTicketRepository $tickets;

    private RecordingEventDispatcher $events;

    private MockClock $clock;

    private EnrolmentTicketIssue $issue;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->hasher = new FakePasswordHasher();
        $this->tickets = new InMemoryEnrolmentTicketRepository();
        $this->events = new RecordingEventDispatcher();
        $this->clock = new MockClock('2026-10-11T12:00:00+00:00');
        $this->issue = new EnrolmentTicketIssue(
            $this->tickets,
            new SymfonyUuidGenerator(),
            new PlatformRandomness(),
            $this->hasher,
            $this->clock,
            $this->events,
        );
    }

    #[Test]
    public function theValueHandedBackIsTheOneTheRowHoldsTheHashOf(): void
    {
        // When
        $issued = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertTrue($this->hasher->verify($issued->ticket->secret, $issued->value));
        static::assertSame($issued->ticket, $this->tickets->find($issued->ticket->id));
    }

    /**
     * Seventy-two hours, which covers a weekend between the day a ticket is issued and the day somebody
     * starts.
     */
    #[Test]
    public function aTicketOpensItsEnrolmentForSeventyTwoHours(): void
    {
        // When
        $issued = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertEquals($this->clock->now()->modify('+72 hours'), $issued->ticket->expiresAt);
    }

    #[Test]
    public function theIssuingIsAnActOfThatAccount(): void
    {
        // When
        $issued = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        $acts = $this->events->of(EnrolmentTicketIssued::class);
        static::assertCount(1, $acts);
        static::assertSame($issued->ticket, $acts[0]->ticket);
        static::assertSame($this->alice->subject, $acts[0]->subject());
    }

    /**
     * One person holds one usable ticket at a time: a link handed over twice is one link, and a link
     * forgotten in a mailbox stops opening anything the day another is issued.
     */
    #[Test]
    public function aSecondTicketTakesTheFirstAway(): void
    {
        // Given
        $first = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // When
        $second = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertNull($this->tickets->find($first->ticket->id));
        static::assertSame([$second->ticket], $this->tickets->unspentOf($this->alice));
    }

    /**
     * Every unspent ticket of that person goes and not only the newest: a run interrupted between the
     * forgetting and the saving leaves two, and the next issuing takes them all.
     */
    #[Test]
    public function everyUnspentTicketOfThatPersonGoes(): void
    {
        // Given
        $first = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
        $second = new EnrolmentTicket(
            Uuid::v7(),
            $this->alice,
            $this->hasher->hash('the value of another link'),
            $this->clock->now(),
            $this->clock->now()->modify('+72 hours'),
        );
        $this->tickets->save($second);

        // When
        $third = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame([$third->ticket], $this->tickets->unspentOf($this->alice));
        static::assertNull($this->tickets->find($first->ticket->id));
        static::assertNull($this->tickets->find($second->id));
    }

    /**
     * A ticket of somebody else is not taken away: the walk reads one person.
     */
    #[Test]
    public function theTicketOfAnotherPersonIsLeftWhereItIs(): void
    {
        // Given
        $bob = Fixtures::user($this->alice->tenant, 'bob', 'bob-subject');
        $theirs = $this->issue->issue($bob, Fixtures::context($this->clock->now()));

        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($theirs->ticket, $this->tickets->find($theirs->ticket->id));
    }

    /**
     * A ticket already spent is a trace of what happened and not a link: issuing another leaves it.
     */
    #[Test]
    public function aTicketAlreadySpentIsLeftWhereItIs(): void
    {
        // Given
        $spent = $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
        $spent->ticket->spend($this->clock->now());
        $this->tickets->save($spent->ticket);

        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));

        // Then
        static::assertSame($spent->ticket, $this->tickets->find($spent->ticket->id));
    }

    #[Test]
    public function aDisabledPersonGetsNoTicket(): void
    {
        // Given
        $this->alice->disable($this->clock->now());

        // Then
        $this->expectException(EnrolmentTicketRefusedException::class);
        $this->expectExceptionMessageIs('The account of "alice" is disabled; a ticket would open nothing.');

        // When
        $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
    }

    #[Test]
    public function nothingIsWrittenForADisabledPerson(): void
    {
        // Given
        $this->alice->disable($this->clock->now());

        // When
        try {
            $this->issue->issue($this->alice, Fixtures::context($this->clock->now()));
        } catch (EnrolmentTicketRefusedException) {
            // the refusal is read by the test above
        }

        // Then
        static::assertSame([], $this->tickets->unspentOf($this->alice));
        static::assertSame([], $this->events->of(EnrolmentTicketIssued::class));
    }
}
