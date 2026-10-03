<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\MessageHandler;

use Beffroi\Bundle\Configuration\JournalSection;
use Beffroi\Bundle\Message\ForgetTheActsPastTheirRetention;
use Beffroi\Bundle\Tests\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\JournalInterface;
use Doctrine\DBAL\Connection;
use Psr\Clock\ClockInterface;
use PHPUnit\Framework\Attributes\Test;
use function sprintf;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #454: the journal keeps an act for as long as the deployment says and the timed step forgets the
 * rest. Six months by default, the duration the deliberation 2021-122 of the CNIL holds for a log of
 * connections.
 */
final class TheJournalIsForgottenInTimeTest extends DatabaseTestCase
{
    #[Test]
    public function anActPastTheRetentionIsForgotten(): void
    {
        // Given
        self::anAct(sprintf('-%d days', JournalSection::DEFAULT_RETENTION + 1));

        // When
        self::tick();

        // Then
        static::assertSame(0, self::kept());
    }

    #[Test]
    public function anActInsideTheRetentionIsKept(): void
    {
        // Given
        self::anAct(sprintf('-%d days', JournalSection::DEFAULT_RETENTION - 1));

        // When
        self::tick();

        // Then
        static::assertSame(1, self::kept());
    }

    /**
     * A count read from the database, narrowed where it is read: a driver answers a number as whatever its
     * platform calls one.
     */
    private static function counted(string $sql): int
    {
        $value = self::service('doctrine.dbal.default_connection', Connection::class)->fetchOne($sql);
        static::assertIsNumeric($value);

        return (int) $value;
    }

    private static function tick(): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch(new ForgetTheActsPastTheirRetention());
        self::reload();
    }

    private static function kept(): int
    {
        return self::counted('SELECT COUNT(*) FROM beffroi_journal');
    }

    private static function anAct(string $ago): void
    {
        $user = self::user('alice');
        self::service('test.beffroi.journal', JournalInterface::class)
            ->record(new JournalEntry(
                Uuid::v7(),
                self::tenant(),
                UserAuthenticated::NAME,
                self::service('clock', ClockInterface::class)->now()->modify($ago),
                self::context(),
                $user->subject,
            ));
    }
}
