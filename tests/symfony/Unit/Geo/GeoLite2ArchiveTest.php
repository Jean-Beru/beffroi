<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Unit\Geo;

use Beffroi\Bundle\Geo\GeoLite2Archive;
use Beffroi\Bundle\Tests\Fixture\MaxMindDatabase;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Issue #473: the database inside what MaxMind serves, taken out of the archive and nothing else with it.
 */
final class GeoLite2ArchiveTest extends TestCase
{
    #[Test]
    public function theDatabaseIsTakenOutOfTheArchiveByteForByte(): void
    {
        // Given
        $database = MaxMindDatabase::city();

        // When
        $taken = GeoLite2Archive::database(MaxMindDatabase::archived($database));

        // Then
        static::assertSame($database, $taken);
    }

    /**
     * A deployment that unpacked an archive by hand names the database itself, which is a file this takes
     * as it stands.
     */
    #[Test]
    public function aDatabaseThatIsNotInAnArchiveIsTakenAsItStands(): void
    {
        // Given
        $database = MaxMindDatabase::asn();

        // When / Then
        static::assertSame($database, GeoLite2Archive::database($database));
    }

    #[Test]
    #[DataProvider('provideWhatIsNotADatabase')]
    public function whatHoldsNoDatabaseIsRefused(string $archive, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        GeoLite2Archive::database($archive);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideWhatIsNotADatabase(): iterable
    {
        yield 'a file that is neither' => ['what the source answered instead', 'what it holds is not a MaxMind DB file'];
        yield 'an archive of other things' => [
            MaxMindDatabase::archived('not a database', 'GeoLite2-City_20260101'),
            'what it holds is not a MaxMind DB file',
        ];
        yield 'an archive of no database' => [
            MaxMindDatabase::archived('the terms of the licence', name: 'LICENSE.txt'),
            'no member of the archive is a ".mmdb" database',
        ];
    }
}
