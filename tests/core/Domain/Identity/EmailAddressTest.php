<?php

declare(strict_types=1);

namespace Heidi\Core\Tests\Domain\Identity;

use Heidi\Core\Domain\Identity\EmailAddress;
use Heidi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class EmailAddressTest extends TestCase
{
    #[Test]
    #[DataProvider('provideValidAddresses')]
    public function itAcceptsAnAddress(string $value): void
    {
        // When / Then
        static::assertSame($value, (string) new EmailAddress($value));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideValidAddresses(): iterable
    {
        yield 'ascii' => ['alice@acme.example'];
        yield 'unicode local part' => ['zoé@acme.example'];
    }

    #[Test]
    #[DataProvider('provideInvalidAddresses')]
    public function itRejectsAnInvalidAddress(string $value): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);

        // When
        new EmailAddress($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideInvalidAddresses(): iterable
    {
        yield 'empty' => [''];
        yield 'no at sign' => ['alice.acme.example'];
        yield 'no domain' => ['alice@'];
        yield 'space' => ['alice smith@acme.example'];
    }
}
