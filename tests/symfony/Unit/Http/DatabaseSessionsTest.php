<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use App\Doctrine\PersonalData\TenantScopedEncrypter;
use App\Http\DatabaseSessions;
use App\Tests\Symfony\Fixture\AmbientTenant;
use Beffroi\Core\Tests\Fixture\Fixtures;
use function hash;
use PDO;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\KeyManagement\StoredEnvelopeEncrypter;
use Symfony\Component\KeyManagement\Test\InMemoryDataKeyStore;

/**
 * Decision 0053
 */
final class DatabaseSessionsTest extends TestCase
{
    private const string COOKIE = 'r8Kq2mZ7tVb1sNc4';

    private const string ANOTHER_COOKIE = 'Xp3vQ9wE5yLh0aJd';

    #[Test]
    public function aSessionIsReadBackUnderTheIdentifierOfItsCookie(): void
    {
        // Given
        $database = self::database();
        $sealer = self::sealer();
        self::write(new DatabaseSessions($database, $sealer), 'the data of the browser');

        // When
        $read = self::read(new DatabaseSessions($database, $sealer));

        // Then
        static::assertSame('the data of the browser', $read);
    }

    #[Test]
    public function aRowIsKeyedByTheHashAndNeverByTheIdentifierOfItsCookie(): void
    {
        // Given
        $database = self::database();

        // When
        self::write(new DatabaseSessions($database, self::sealer()), 'the data of the browser');

        // Then
        static::assertSame([hash('sha256', self::COOKIE)], self::column($database, 'SELECT sess_id FROM beffroi_session'));
    }

    /**
     * Decision 0011
     */
    #[Test]
    public function theDataOfASessionIsSealedSoThatTheTableHoldsNoneOfIt(): void
    {
        // Given
        $database = self::database();

        // When
        self::write(new DatabaseSessions($database, self::sealer()), 'the data of the browser');

        // Then
        $stored = self::column($database, 'SELECT sess_data FROM beffroi_session');
        static::assertCount(1, $stored);
        static::assertStringNotContainsString('the data of the browser', $stored[0]);
    }

    #[Test]
    public function aRowSealedUnderADataKeyTheTenantNoLongerHoldsIsNoSession(): void
    {
        // Given
        $database = self::database();
        self::write(new DatabaseSessions($database, self::sealer()), 'the data of the browser');

        // When
        $read = self::read(new DatabaseSessions($database, self::sealer()));

        // Then
        static::assertSame('', $read);
    }

    #[Test]
    public function aRowMovedUnderTheHashOfAnotherIdentifierIsNoSession(): void
    {
        // Given
        $database = self::database();
        $sealer = self::sealer();
        self::write(new DatabaseSessions($database, $sealer), 'the data of the browser');
        $moved = $database->prepare('UPDATE beffroi_session SET sess_id = :moved');
        $moved->execute(['moved' => hash('sha256', self::ANOTHER_COOKIE)]);

        // When
        $read = self::read(new DatabaseSessions($database, $sealer), self::ANOTHER_COOKIE);

        // Then
        static::assertSame('', $read);
    }

    /**
     * Decision 0011
     */
    #[Test]
    public function aValueSealedForAColumnOfAPersonIsNoSession(): void
    {
        // Given
        $database = self::database();
        $sealer = self::sealer();
        self::write(new DatabaseSessions($database, $sealer), 'the data of the browser');
        $replaced = $database->prepare('UPDATE beffroi_session SET sess_data = :sealed');
        $replaced->execute(['sealed' => (string) $sealer->encrypt('user', 'what a person wrote')]);

        // When
        $read = self::read(new DatabaseSessions($database, $sealer));

        // Then
        static::assertSame('', $read);
    }

    private static function database(): PDO
    {
        $database = new PDO('sqlite::memory:');
        new DatabaseSessions($database, self::sealer())->createTable();

        return $database;
    }

    /**
     * A store of data keys of its own: two sealers hold no key in common.
     */
    private static function sealer(): TenantScopedEncrypter
    {
        return new TenantScopedEncrypter(new StoredEnvelopeEncrypter(new InMemoryDataKeyStore()), new AmbientTenant(Fixtures::tenant('acme')));
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

    private static function read(DatabaseSessions $sessions, string $cookie = self::COOKIE): string
    {
        $sessions->open('', 'beffroi');
        $read = $sessions->read($cookie);
        $sessions->close();
        static::assertIsString($read);

        return $read;
    }
}
