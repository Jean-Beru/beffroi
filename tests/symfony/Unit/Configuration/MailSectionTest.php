<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Configuration;

use App\Configuration\MailSection;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

/**
 * Decision 0048, Decision 0030
 */
final class MailSectionTest extends TestCase
{
    #[Test]
    #[DataProvider('provideDsns')]
    public function mailIsOnWhileADsnIsNamed(?string $dsn, bool $on): void
    {
        // When / Then
        static::assertSame($on, MailSection::role($dsn, 'no-reply@op.test')->on);
    }

    /**
     * @return iterable<string, array{?string, bool}>
     */
    public static function provideDsns(): iterable
    {
        yield 'none' => [null, false];
        yield 'a server' => ['smtp://mail.op.test:587', true];
    }

    #[Test]
    public function mailThatIsOffAsksForNoSender(): void
    {
        // When / Then
        static::assertFalse(MailSection::role(null, null)->on);
    }

    #[Test]
    public function aDsnWithoutASenderIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "mail.sender" names the address the mail of this deployment is written from, and none is named.');

        // When
        MailSection::role('smtp://mail.op.test:587', null);
    }

    /**
     * RFC 5322 §3.4
     */
    #[Test]
    public function aSenderThatIsNoAddressIsRefused(): void
    {
        // Then
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessageIs('The "beffroi" configuration key "mail.sender" is not an address, alone or behind a name.');

        // When
        MailSection::role('smtp://mail.op.test:587', 'the operator');
    }

    /**
     * RFC 5322 §3.4
     */
    #[Test]
    #[DataProvider('provideSenders')]
    public function theSenderIsAnAddressAloneOrBehindAName(string $sender, string $writtenAs): void
    {
        // When / Then
        static::assertSame($writtenAs, MailSection::sender($sender)->toString());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideSenders(): iterable
    {
        yield 'an address' => ['no-reply@op.test', 'no-reply@op.test'];
        yield 'an address behind a name' => ['Acme <no-reply@acme.example>', '"Acme" <no-reply@acme.example>'];
    }
}
