<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Enrolment;

use Beffroi\Core\Domain\Enrolment\EnrolmentTicket;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Tests\Fixture\FakePasswordHasher;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class EnrolmentTicketTest extends TestCase
{
    private User $alice;

    private DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->alice = Fixtures::user();
        $this->now = Fixtures::now();
    }

    #[Test]
    public function aTicketIsOfTheTenantOfItsPerson(): void
    {
        // When / Then
        static::assertTrue($this->ticket()->belongsTo($this->alice->tenant));
    }

    #[Test]
    public function aTicketOfAnotherTenantIsNotThisOne(): void
    {
        // When / Then
        static::assertFalse($this->ticket()->belongsTo(Fixtures::tenant('other', 'https://id.other.example')));
    }

    #[Test]
    public function aFreshTicketOpensItsEnrolment(): void
    {
        // When / Then
        static::assertTrue($this->ticket()->opens($this->now));
    }

    #[Test]
    public function aTicketSpentOpensNothingMore(): void
    {
        // Given
        $ticket = $this->ticket();

        // When
        $ticket->spend($this->now);

        // Then
        static::assertSame($this->now, $ticket->spentAt);
        static::assertTrue($ticket->isSpent());
        static::assertFalse($ticket->opens($this->now));
    }

    #[Test]
    public function aTicketIsNotSpentTwice(): void
    {
        // Given
        $ticket = $this->ticket();
        $ticket->spend($this->now);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('This ticket is spent already.');

        // When
        $ticket->spend($this->now->modify('+1 minute'));
    }

    #[Test]
    public function aTicketOpensNothingOnceItsTimeHasPassed(): void
    {
        // Given
        $ticket = $this->ticket();

        // When / Then
        static::assertTrue($ticket->isExpired($this->now->modify('+72 hours')));
        static::assertFalse($ticket->opens($this->now->modify('+72 hours')));
        static::assertTrue($ticket->opens($this->now->modify('+71 hours 59 minutes')));
    }

    #[Test]
    public function aTicketOfADisabledPersonOpensNothing(): void
    {
        // Given
        $ticket = $this->ticket();
        $this->alice->disable($this->now);

        // When / Then
        static::assertFalse($ticket->opens($this->now));
    }

    #[Test]
    public function aTicketExpiresAfterItWasIssued(): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs('A ticket expires after it was issued.');

        // When
        new EnrolmentTicket(Uuid::v7(), $this->alice, new FakePasswordHasher()->hash('value'), $this->now, $this->now);
    }

    private function ticket(): EnrolmentTicket
    {
        return new EnrolmentTicket(
            Uuid::v7(),
            $this->alice,
            new FakePasswordHasher()->hash('the value of the link'),
            $this->now,
            $this->now->modify('+72 hours'),
        );
    }
}
