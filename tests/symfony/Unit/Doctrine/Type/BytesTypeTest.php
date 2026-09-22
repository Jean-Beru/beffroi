<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Doctrine\Type;

use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Doctrine\DBAL\Types\ConversionException;
use Heidi\Bundle\Doctrine\Type\BytesType;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Architecture §5.3: raw bytes in a text column as base64url (RFC 4648 §5), never a stream.
 */
final class BytesTypeTest extends TestCase
{
    #[Test]
    #[DataProvider('provideBytes')]
    public function bytesGoToTheDatabaseAsBase64UrlWithoutPadding(string $bytes, string $stored): void
    {
        // When / Then
        static::assertSame($stored, new BytesType()->convertToDatabaseValue($bytes, new SQLitePlatform()));
    }

    #[Test]
    #[DataProvider('provideBytes')]
    public function bytesComeBackEqual(string $bytes, string $stored): void
    {
        // When / Then
        static::assertSame($bytes, new BytesType()->convertToPHPValue($stored, new SQLitePlatform()));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideBytes(): iterable
    {
        yield 'empty' => ['', ''];
        yield 'one byte' => ["\xfb", '-w'];
        yield 'two bytes' => ["\xfb\xff", '-_8'];
        yield 'three bytes' => ["\xfb\xff\xbf", '-_-_'];
        yield 'a credential id' => ['credential-id', 'Y3JlZGVudGlhbC1pZA'];
    }

    #[Test]
    public function nullGoesBothWaysAsNull(): void
    {
        // Given
        $type = new BytesType();

        // When / Then
        static::assertNull($type->convertToDatabaseValue(null, new SQLitePlatform()));
        static::assertNull($type->convertToPHPValue(null, new SQLitePlatform()));
    }

    #[Test]
    public function whatIsNotAStringIsNotStored(): void
    {
        // Then
        $this->expectException(ConversionException::class);

        // When
        new BytesType()->convertToDatabaseValue(12, new SQLitePlatform());
    }

    #[Test]
    #[DataProvider('provideUnreadable')]
    public function whatTheDatabaseHoldsThatIsNotBase64UrlIsNotRead(mixed $stored): void
    {
        // Then
        $this->expectException(ConversionException::class);

        // When
        new BytesType()->convertToPHPValue($stored, new SQLitePlatform());
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideUnreadable(): iterable
    {
        yield 'not base64url' => ['***'];
        yield 'not a string' => [12];
    }

    #[Test]
    public function theColumnIsText(): void
    {
        // When / Then
        static::assertSame('TEXT', new BytesType()->getSQLDeclaration([], new PostgreSQLPlatform()));
    }
}
