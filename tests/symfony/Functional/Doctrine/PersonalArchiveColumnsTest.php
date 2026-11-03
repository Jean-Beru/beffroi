<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Doctrine;

use App\Tests\Symfony\Functional\Doctrine\PersonalData\RawRows;
use App\Tests\Symfony\Functional\Doctrine\PersonalData\SealedRows;
use Beffroi\Core\Domain\Archive\PersonalArchive;
use Beffroi\Core\Domain\Event\PersonAskedForTheirArchive;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\PersonalArchiveRepositoryInterface;
use DateTimeImmutable;
use Doctrine\DBAL\Connection;
use Psr\Clock\ClockInterface;
use function sprintf;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #453 and decision 0011: the archive a person asked for is sealed at rest like everything else, in
 * a scope of its own.
 *
 * It is the one column of this schema where everything the other families seal stands in clear at once,
 * which is why it carries no exemption: the whole point of sealing a column is that a dump of the
 * database gives nothing away, and a dump that read this one would give away all of it.
 *
 * The other half of what this holds is the write path. The archive is built off the request, from a
 * handler of the bus, and a sealed column written with no ambient tenant is refused rather than written
 * under a wrong scope: what is played below is the act of a person consumed by the bus with no request in
 * sight.
 */
final class PersonalArchiveColumnsTest extends DatabaseTestCase
{
    private const string DOCUMENT = SealedRows::VALUES['beffroi_personal_archive']['content'];

    #[Test]
    public function theDocumentIsReadBackAsItWasWritten(): void
    {
        // Given
        $saved = self::built(self::user());
        self::reload();

        // When
        $read = self::archives()->find(self::tenant(), $saved->id) ?? static::fail('The archive was not stored.');

        // Then
        static::assertSame(self::DOCUMENT, $read->content);
    }

    #[Test]
    public function theColumnHoldsNoneOfTheDocument(): void
    {
        // Given
        self::built(self::user());
        self::reload();

        // When
        $stored = self::row()['content'];

        // Then
        static::assertStringNotContainsString('Augusta Ada King-Noel', $stored);
        static::assertStringNotContainsString('ada@example.org', $stored);
    }

    /**
     * The archive is built where no request is: the act reaches a handler of the bus, which seals the
     * document under the data key of the tenant of the process.
     */
    #[Test]
    public function anArchiveAskedForIsBuiltAndSealedOffTheRequest(): void
    {
        // Given
        $user = self::user();
        $archive = PersonalArchive::asked(Uuid::v7(), $user, self::onTheClock());
        self::archives()->save($archive);

        // When
        self::service('event.bus', MessageBusInterface::class)
            ->dispatch(new PersonAskedForTheirArchive(self::onTheClock(), $user->tenant, $archive->id, $user->subject, self::context()));
        self::reload();

        // Then
        $read = self::archives()->find(self::tenant(), $archive->id) ?? static::fail('The archive was not stored.');
        static::assertTrue($read->isReady());
        static::assertStringNotContainsString($user->subject->value, self::row()['content']);
    }

    /**
     * A row of an archive still being built holds no document, which is what lets a page say so rather
     * than give nothing.
     */
    #[Test]
    public function anArchiveStillBeingBuiltHoldsNoDocument(): void
    {
        // Given
        $archive = PersonalArchive::asked(Uuid::v7(), self::user(), self::onTheClock());
        self::archives()->save($archive);
        self::reload();

        // When
        $rows = RawRows::of(self::connection(), 'beffroi_personal_archive', ['content', 'built_at']);

        // Then
        static::assertNull($rows[0]['content']);
        static::assertNull($rows[0]['built_at']);
    }

    /**
     * The one row of the table as the database holds it: a column that holds nothing is a column with
     * nothing to assert against, so a null fails here and not silently in the test that reads it.
     *
     * @return array<string, string>
     */
    private static function row(): array
    {
        $rows = RawRows::of(self::connection(), 'beffroi_personal_archive', ['content']);
        static::assertCount(1, $rows);

        $row = [];
        foreach ($rows[0] as $column => $value) {
            $row[$column] = $value ?? static::fail(sprintf('beffroi_personal_archive.%s holds nothing.', $column));
        }

        return $row;
    }

    private static function built(User $user): PersonalArchive
    {
        $archive = PersonalArchive::asked(Uuid::v7(), $user, self::onTheClock());
        $archive->fill(self::DOCUMENT, self::onTheClock());
        self::archives()->save($archive);

        return $archive;
    }

    /**
     * The clock the application reads and not the fixture date of this suite: an archive expires, so a row
     * dated a month before the run is a row the assembly is right to leave alone.
     */
    private static function onTheClock(): DateTimeImmutable
    {
        return self::service('clock', ClockInterface::class)->now();
    }

    private static function archives(): PersonalArchiveRepositoryInterface
    {
        return self::service('test.beffroi.archives', PersonalArchiveRepositoryInterface::class);
    }

    private static function connection(): Connection
    {
        return self::service('doctrine.dbal.default_connection', Connection::class);
    }
}
