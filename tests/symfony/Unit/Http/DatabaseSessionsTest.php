<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Http\DatabaseSessions;
use function array_map;
use PDO;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function strlen;

/**
 * Decision 0053
 */
final class DatabaseSessionsTest extends TestCase
{
    private const string COOKIE = 'r8Kq2mZ7tVb1sNc4';

    #[Test]
    public function aSessionIsReadBackUnderTheIdentifierOfItsCookie(): void
    {
        // Given
        $database = self::database();
        self::write(new DatabaseSessions($database, 'secret'), 'the data of the browser');

        // When
        $read = self::read(new DatabaseSessions($database, 'secret'));

        // Then
        static::assertSame('the data of the browser', $read);
    }

    #[Test]
    public function aRowIsKeyedByAnHmacAndNeverByTheIdentifierOfItsCookie(): void
    {
        // Given
        $database = self::database();

        // When
        self::write(new DatabaseSessions($database, 'secret'), 'the data of the browser');

        // Then
        $keys = self::column($database, 'SELECT sess_id FROM beffroi_session');
        static::assertSame([64], array_map(strlen(...), $keys));
        static::assertNotContains(self::COOKIE, $keys);
    }

    #[Test]
    public function theDataOfASessionIsSealedSoThatTheTableHoldsNoneOfIt(): void
    {
        // Given
        $database = self::database();

        // When
        self::write(new DatabaseSessions($database, 'secret'), 'the data of the browser');

        // Then
        $stored = self::column($database, 'SELECT sess_data FROM beffroi_session');
        static::assertCount(1, $stored);
        static::assertStringNotContainsString('the data of the browser', $stored[0]);
    }

    #[Test]
    public function anotherSecretReadsNoSession(): void
    {
        // Given
        $database = self::database();
        self::write(new DatabaseSessions($database, 'secret'), 'the data of the browser');

        // When
        $read = self::read(new DatabaseSessions($database, 'another secret'));

        // Then
        static::assertSame('', $read);
    }

    private static function database(): PDO
    {
        $database = new PDO('sqlite::memory:');
        new DatabaseSessions($database, 'secret')->createTable();

        return $database;
    }

    /**
     * @return list<string>
     */
    private static function column(PDO $database, string $query): array
    {
        $statement = $database->query($query);
        static::assertNotFalse($statement);
        $values = [];
        foreach ($statement->fetchAll(PDO::FETCH_COLUMN) as $value) {
            static::assertIsString($value);
            $values[] = $value;
        }

        return $values;
    }

    private static function write(DatabaseSessions $sessions, string $data): void
    {
        $sessions->open('', 'beffroi');
        $sessions->read(self::COOKIE);
        $sessions->write(self::COOKIE, $data);
        $sessions->close();
    }

    private static function read(DatabaseSessions $sessions): string
    {
        $sessions->open('', 'beffroi');
        $read = $sessions->read(self::COOKIE);
        $sessions->close();
        static::assertIsString($read);

        return $read;
    }
}
