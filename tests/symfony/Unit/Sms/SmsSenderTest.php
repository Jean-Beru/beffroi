<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Sms;

use App\Messenger\NotificationNotDeliveredException;
use App\Sms\SmsSender;
use App\Tests\Symfony\Fixture\RecordingSmsTransport;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Decision 0048
 */
final class SmsSenderTest extends TestCase
{
    private const string NUMBER = '+33600000000';

    private RecordingSmsTransport $transport;

    protected function setUp(): void
    {
        $this->transport = new RecordingSmsTransport();
    }

    #[Test]
    public function aPersonIsTextedAtTheNumberTheyVerified(): void
    {
        // When
        $sent = new SmsSender($this->transport)->send(self::verified(), 'Open your account to answer.');

        // Then
        static::assertTrue($sent);
        static::assertCount(1, $this->transport->sent);
        static::assertSame(self::NUMBER, $this->transport->sent[0]->getPhone());
        static::assertSame('Open your account to answer.', $this->transport->sent[0]->getSubject());
    }

    #[Test]
    #[DataProvider('provideNumbersNobodyVerified')]
    public function aPersonWhoseNumberNobodyVerifiedIsTextedNothing(?string $number): void
    {
        // Given
        $user = Fixtures::user();
        $user->changePhoneNumber($number, false, Fixtures::now());

        // When
        $sent = new SmsSender($this->transport)->send($user, 'Open your account to answer.');

        // Then
        static::assertFalse($sent);
        static::assertSame([], $this->transport->sent);
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideNumbersNobodyVerified(): iterable
    {
        yield 'no number' => [null];
        yield 'a number nobody verified' => [self::NUMBER];
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aTransportThatDidNotTakeTheTextBringsTheLaneBack(): void
    {
        // Given
        $sender = new SmsSender(new RecordingSmsTransport(refusing: true));

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIs('The SMS transport did not take the message (Symfony\Component\Notifier\Exception\TransportException).');

        // When
        $sender->send(self::verified(), 'Open your account to answer.');
    }

    /**
     * Decision 0011
     */
    #[Test]
    public function theFailureLeavesOutWhatTheProviderSaidOfTheNumber(): void
    {
        // Given
        $sender = new SmsSender(new RecordingSmsTransport(refusing: true));

        // When
        try {
            $sender->send(self::verified(), 'Open your account to answer.');
            static::fail('The transport took the text.');
        } catch (NotificationNotDeliveredException $failure) {
            // Then
            static::assertStringNotContainsString(self::NUMBER, $failure->getMessage());
        }
    }

    private static function verified(): User
    {
        $user = Fixtures::user();
        $user->changePhoneNumber(self::NUMBER, true, Fixtures::now());

        return $user;
    }
}
