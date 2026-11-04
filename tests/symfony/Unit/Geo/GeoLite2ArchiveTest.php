<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Geo;

use function chr;
use function file_get_contents;
use function file_put_contents;
use App\Geo\GeoLite2Archive;
use App\Tests\Symfony\Fixture\MaxMindDatabase;
use Beffroi\Core\Exception\InvalidArgumentException;
use function ord;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;
use function strlen;
use Symfony\Component\Filesystem\Filesystem;
use function sys_get_temp_dir;
use function uniqid;

final class GeoLite2ArchiveTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/beffroi-integration-tests/geoip-archive-' . uniqid();
        new Filesystem()->mkdir($this->directory);
    }

    protected function tearDown(): void
    {
        new Filesystem()->remove($this->directory);
    }

    #[Test]
    public function theDatabaseIsTakenOutOfTheArchiveByteForByte(): void
    {
        // Given
        $database = MaxMindDatabase::city();
        $archive = $this->file(MaxMindDatabase::archived($database));

        // When
        GeoLite2Archive::unpack($archive, $this->directory . '/taken.mmdb');

        // Then
        static::assertSame($database, file_get_contents($this->directory . '/taken.mmdb'));
    }

    #[Test]
    public function aDatabaseThatIsNotInAnArchiveIsTakenAsItStands(): void
    {
        // Given
        $database = MaxMindDatabase::asn();
        $file = $this->file($database);

        // When
        GeoLite2Archive::unpack($file, $this->directory . '/taken.mmdb');

        // Then
        static::assertSame($database, file_get_contents($this->directory . '/taken.mmdb'));
    }

    #[Test]
    public function aMemberThatIsNotTheDatabaseIsReadPastWhateverItHolds(): void
    {
        // Given
        $database = MaxMindDatabase::city();
        $archive = $this->file(MaxMindDatabase::archived($database, copyright: MaxMindDatabase::tarred(MaxMindDatabase::asn())));

        // When
        GeoLite2Archive::unpack($archive, $this->directory . '/taken.mmdb');

        // Then
        static::assertSame($database, file_get_contents($this->directory . '/taken.mmdb'));
    }

    #[Test]
    #[DataProvider('provideWhatIsNotADatabase')]
    public function whatHoldsNoDatabaseIsRefused(string $archive, string $message): void
    {
        // Given
        $file = $this->file($archive);

        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIs($message);

        // When
        GeoLite2Archive::unpack($file, $this->directory . '/taken.mmdb');
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
        // A gzip header followed by a block of the reserved type (RFC 1951 §3.2.3, BTYPE 11).
        yield 'an archive whose data is not deflated' => [
            "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03" . str_repeat("\xff", 64),
            'the archive is gzipped and cannot be unpacked',
        ];
        yield 'an archive whose check does not hold' => [
            self::withAnotherCheck(MaxMindDatabase::archived(MaxMindDatabase::city(), licence: str_repeat('The terms of the licence. ', 8_192))),
            'the archive is gzipped and cannot be unpacked',
        ];
    }

    /**
     * RFC 1952 §2.3.1
     */
    private static function withAnotherCheck(string $archive): string
    {
        $offset = strlen($archive) - 8;
        $archive[$offset] = chr(ord($archive[$offset]) ^ 0xFF);

        return $archive;
    }

    private function file(string $contents): string
    {
        $path = $this->directory . '/source';
        file_put_contents($path, $contents);

        return $path;
    }
}
