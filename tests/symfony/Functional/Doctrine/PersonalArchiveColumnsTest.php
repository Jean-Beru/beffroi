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
 * Decision 0011
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
