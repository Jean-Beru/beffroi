<?php

declare(strict_types=1);

namespace Beffroi\Core\Tests\Domain\Identity;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Exception\InvalidArgumentException;
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

    /**
     * RFC 4343 §3: a domain is compared without regard to ASCII case, which is how an upstream provider
     * answers for one (issue #781).
     */
    #[Test]
    #[DataProvider('provideDomains')]
    public function itNamesItsDomainInLowercase(string $value, string $domain): void
    {
        // When / Then
        static::assertSame($domain, new EmailAddress($value)->domain());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideDomains(): iterable
    {
        yield 'in lowercase' => ['alice@acme.example', 'acme.example'];
        yield 'in another case' => ['Alice@Acme.EXAMPLE', 'acme.example'];
        yield 'after the last at sign of a quoted local part' => ['"alice@home"@acme.example', 'acme.example'];
    }

    /**
     * RFC 5321 §2.4: the local part is the receiving server's business and so case-sensitive to everyone
     * else, the domain is not.
     */
    #[Test]
    #[DataProvider('provideMailboxes')]
    public function itTellsTheSameMailbox(string $one, string $other, bool $same): void
    {
        // When / Then
        static::assertSame($same, new EmailAddress($one)->isTheSameMailboxAs(new EmailAddress($other)));
    }

    /**
     * @return iterable<string, array{string, string, bool}>
     */
    public static function provideMailboxes(): iterable
    {
        yield 'as it was written' => ['alice@acme.example', 'alice@acme.example', true];
        yield 'the domain in another case' => ['alice@acme.example', 'alice@ACME.example', true];
        yield 'the local part in another case' => ['alice@acme.example', 'Alice@acme.example', false];
        yield 'another domain' => ['alice@acme.example', 'alice@acme.test', false];
        yield 'another local part' => ['alice@acme.example', 'bob@acme.example', false];
    }
}
