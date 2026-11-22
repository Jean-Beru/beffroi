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
use Psr\Log\NullLogger;
use Symfony\Component\Notifier\Exception\InvalidArgumentException;
use Symfony\Component\Notifier\Exception\UnsupportedSchemeException;
use Symfony\Component\Notifier\Transport\Dsn;
use Symfony\Component\Notifier\Transport\TransportInterface;

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
    public function aPersonIsTextedAtTheNumberMarkedVerified(): void
    {
        // When
        $sent = $this->sender()->send(self::verified(), 'Open your account to answer.');

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
        $sent = $this->sender()->send($user, 'Open your account to answer.');

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
        $sender = $this->sender(new RecordingSmsTransport(refusing: true));

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
        $sender = $this->sender(new RecordingSmsTransport(refusing: true));

        // When
        try {
            $sender->send(self::verified(), 'Open your account to answer.');
            static::fail('The transport took the text.');
        } catch (NotificationNotDeliveredException $failure) {
            // Then
            static::assertStringNotContainsString(self::NUMBER, $failure->getMessage());
        }
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aDsnNoInstalledBridgeReadsTextsNothing(): void
    {
        // Given
        $sender = new SmsSender(static fn (): TransportInterface => throw new UnsupportedSchemeException(new Dsn('example://default')), new NullLogger());

        // When
        $sent = $sender->send(self::verified(), 'Open your account to answer.');

        // Then
        static::assertFalse($sent);
    }

    #[Test]
    public function aTextTheProviderWillNeverCarryIsTextedNothing(): void
    {
        // Given
        $transport = self::createStub(TransportInterface::class);
        $transport->method('send')->willThrowException(new InvalidArgumentException('This provider texts no number of that country.'));
        $sender = new SmsSender(static fn (): TransportInterface => $transport, new NullLogger());

        // When
        $sent = $sender->send(self::verified(), 'Open your account to answer.');

        // Then
        static::assertFalse($sent);
    }

    private function sender(?RecordingSmsTransport $transport = null): SmsSender
    {
        $transport ??= $this->transport;

        return new SmsSender(static fn (): TransportInterface => $transport, new NullLogger());
    }

    private static function verified(): User
    {
        $user = Fixtures::user();
        $user->changePhoneNumber(self::NUMBER, true, Fixtures::now());

        return $user;
    }
}
