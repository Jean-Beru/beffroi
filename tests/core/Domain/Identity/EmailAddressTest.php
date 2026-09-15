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
    public function itAcceptsAnAddressIncludingUnicodeLocalParts(): void
    {
        static::assertSame('alice@acme.example', (string) new EmailAddress('alice@acme.example'));
        static::assertSame('zoé@acme.example', (string) new EmailAddress('zoé@acme.example'));
    }

    #[Test]
    #[DataProvider('provideInvalidAddresses')]
    public function itRejectsAnInvalidAddress(string $value): void
    {
        $this->expectException(InvalidArgumentException::class);

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
