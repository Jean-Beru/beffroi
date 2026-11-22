<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Tenant;

use Beffroi\Core\Domain\Tenant\TenantContact;
use Beffroi\Core\Exception\InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use function str_repeat;

final class TenantContactTest extends TestCase
{
    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    #[DataProvider('provideContacts')]
    public function itKeepsWhatTheTenantWrote(string $contact): void
    {
        // When / Then
        static::assertSame($contact, new TenantContact($contact)->value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideContacts(): iterable
    {
        yield 'an address' => ['security@acme.example'];
        yield 'a number' => ['+33 1 23 45 67 89'];
        yield 'a page' => ['https://help.acme.example/report'];
        yield 'words around them' => ['the help desk, 01 23 45 67 89'];
        yield 'letters of another script' => ['安全チーム security@acme.example'];
        yield 'letters of another script at its end' => ['security@acme.example 安全チーム'];
        yield 'as long as it may be' => [str_repeat('a', TenantContact::MAX_LENGTH)];
    }

    #[Test]
    #[DataProvider('provideRefusedContacts')]
    public function itRefusesWhatAMessageCouldNotCarryAsOneLine(string $contact, string $message): void
    {
        // Then
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains($message);

        // When
        new TenantContact($contact);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideRefusedContacts(): iterable
    {
        yield 'nothing' => ['', 'must not be empty'];
        yield 'a space before it' => [' security@acme.example', 'neither begin nor end with a space'];
        yield 'a line feed behind it' => ["security@acme.example\n", 'neither begin nor end with a space'];
        yield 'a line feed inside it' => ["security@acme.example\nhttps://evil.example", 'one line of text'];
        yield 'a character that turns the text after it around' => ["security@acme.example\u{202E}elpmaxe", 'one line of text'];
        yield 'a character that shows nothing' => ["security@acme\u{200B}.example", 'one line of text'];
        yield 'bytes that are not UTF-8' => ["security@acme.example\xC3", 'is not UTF-8'];
        yield 'too long' => [str_repeat('a', TenantContact::MAX_LENGTH + 1), 'longer than 255 characters'];
    }

    #[Test]
    public function twoContactsWrittenAlikeAreEqual(): void
    {
        // When / Then
        static::assertTrue(new TenantContact('security@acme.example')->equals(new TenantContact('security@acme.example')));
    }

    #[Test]
    #[DataProvider('provideOtherContacts')]
    public function aContactIsNotAnotherOneOrNone(?TenantContact $other): void
    {
        // When / Then
        static::assertFalse(new TenantContact('security@acme.example')->equals($other));
    }

    /**
     * @return iterable<string, array{?TenantContact}>
     */
    public static function provideOtherContacts(): iterable
    {
        yield 'another one' => [new TenantContact('help@acme.example')];
        yield 'none' => [null];
    }
}
