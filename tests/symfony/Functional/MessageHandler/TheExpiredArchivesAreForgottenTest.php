<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\MessageHandler;

use App\Message\ForgetTheExpiredArchives;
use App\Tests\Symfony\Functional\Doctrine\DatabaseTestCase;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use PHPUnit\Framework\Attributes\Test;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453: an archive expires, and the timed step forgets it. There is no duration to configure, every
 * row carrying the date it goes away on: the one file where every sealed column stands in clear at once is
 * not kept for as long as somebody felt like.
 */
final class TheExpiredArchivesAreForgottenTest extends DatabaseTestCase
{
    #[Test]
    public function anArchivePastItsDateIsForgotten(): void
    {
        // Given
        self::anArchive(sprintf('-%d days', PersonalArchive::KEPT_FOR_DAYS + 1));

        // When
        self::tick();

        // Then
        static::assertSame(0, self::kept());
    }

    #[Test]
    public function anArchiveInsideItsDateIsKept(): void
    {
        // Given
        self::anArchive('-1 day');

        // When
        self::tick();

        // Then
        static::assertSame(1, self::kept());
    }

    /**
     * A row whose build never ran goes away on the same date as one whose build did, the expiry being
     * counted from the moment the person asked.
     */
    #[Test]
    public function anArchiveThatWasNeverBuiltIsForgottenAllTheSame(): void
    {
        // Given
        self::anArchive(sprintf('-%d days', PersonalArchive::KEPT_FOR_DAYS + 1), built: false);

        // When
        self::tick();

        // Then
        static::assertSame(0, self::kept());
    }

    private static function tick(): void
    {
        self::service('command.bus', MessageBusInterface::class)->dispatch(new ForgetTheExpiredArchives());
        self::reload();
    }

    private static function kept(): int
    {
        $value = self::service('doctrine.dbal.default_connection', Connection::class)->fetchOne('SELECT COUNT(*) FROM beffroi_personal_archive');
        static::assertIsNumeric($value);

        return (int) $value;
    }

    private static function anArchive(string $ago, bool $built = true): void
    {
        $asked = self::onTheClock()->modify($ago);
        $archive = PersonalArchive::asked(Uuid::v7(), self::user(), $asked);
        if ($built) {
            $archive->fill('{"profile":[]}', $asked);
        }
        self::service('test.beffroi.archives', PersonalArchiveRepositoryInterface::class)->save($archive);
        self::reload();
    }

    /**
     * The clock the application reads and not the fixture date of this suite, as the retention of the
     * journal does: what expires is read against the one clock there is.
     */
    private static function onTheClock(): DateTimeImmutable
    {
        return self::service('clock', ClockInterface::class)->now();
    }
}
