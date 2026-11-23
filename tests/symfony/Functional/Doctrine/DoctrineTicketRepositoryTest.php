<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use Beffroi\Core\Bridge\Password\Algorithm\Argon2id;
use Beffroi\Core\Domain\Credential\PasswordHash;
use Beffroi\Core\Domain\Ticket\PasswordTicket;
use Beffroi\Core\Port\PasswordTicketRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0026
 */
final class DoctrineTicketRepositoryTest extends DatabaseTestCase
{
    #[Test]
    public function aTicketNobodySpentIsHeldUnspent(): void
    {
        // Given
        $ticket = self::stored();

        // When / Then
        static::assertFalse(self::tickets()->holdsSpent($ticket));
    }

    #[Test]
    public function aTicketAnotherRequestSpentIsHeldSpentWhateverTheCopySays(): void
    {
        // Given
        $ticket = self::stored();
        self::spentByAnotherRequest($ticket);

        // When / Then
        static::assertSame([false, true], [$ticket->isSpent(), self::tickets()->holdsSpent($ticket)]);
    }

    #[Test]
    public function aTicketTheStoreNoLongerHoldsIsHeldSpent(): void
    {
        // Given
        $ticket = self::stored();
        self::tickets()->forget($ticket);

        // When / Then
        static::assertTrue(self::tickets()->holdsSpent($ticket));
    }

    /**
     * A ticket read back by this request, as a redemption holds it.
     */
    private static function stored(): PasswordTicket
    {
        $ticket = new PasswordTicket(
            Uuid::v7(),
            self::user(),
            new PasswordHash(new Argon2id(), '$argon2id$the-value-of-a-link'),
            self::now(),
            self::now()->modify('+72 hours'),
        );
        self::tickets()->save($ticket);
        self::reload();

        return self::tickets()->find($ticket->id) ?? static::fail('The ticket was not stored.');
    }

    /**
     * What the redemption of a concurrent request writes: the row, and nothing this request's manager holds.
     */
    private static function spentByAnotherRequest(PasswordTicket $ticket): void
    {
        self::entityManager()
            ->getConnection()
            ->executeStatement(
                'UPDATE beffroi_password_ticket SET spent_at = :now WHERE id = :id',
                [
                    'now' => self::now()->modify('+1 minute')->format('Y-m-d H:i:s'),
                    'id' => $ticket->id,
                ],
                [
                    'id' => UuidType::NAME,
                ],
            );
    }

    private static function tickets(): PasswordTicketRepositoryInterface
    {
        return self::service('test.beffroi.password_ticket_store', PasswordTicketRepositoryInterface::class);
    }
}
