<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Sms;

use App\Sms\SmsSender;
use App\Tests\Symfony\Fixture\RecordingSmsTransport;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Notifier\Transport\TransportInterface;

/**
 * NIST SP 800-63B-4 §4.2.1.2, decision 0048
 */
final class SmsSenderConfirmationTest extends TestCase
{
    private const string NUMBER = '+33600000000';

    private RecordingSmsTransport $transport;

    protected function setUp(): void
    {
        $this->transport = new RecordingSmsTransport();
    }

    #[Test]
    #[DataProvider('provideVerifications')]
    public function theConfirmationIsTextedToTheNumberItEstablishesWhateverItsVerification(bool $verified): void
    {
        // Given
        $user = Fixtures::user();
        $user->changePhoneNumber(self::NUMBER, $verified, Fixtures::now());

        // When
        $sent = $this->sender()->sendTheConfirmation($user, self::NUMBER, 'Your code is 123456.');

        // Then
        static::assertTrue($sent);
        static::assertSame([self::NUMBER, 'Your code is 123456.'], [$this->transport->sent[0]->getPhone(), $this->transport->sent[0]->getSubject()]);
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function provideVerifications(): iterable
    {
        yield 'a number nobody verified yet' => [false];
        yield 'a number verified meanwhile' => [true];
    }

    #[Test]
    #[DataProvider('provideNumbersThePersonNoLongerHolds')]
    public function theConfirmationOfANumberThePersonNoLongerHoldsIsTextedNothing(?string $held): void
    {
        // Given
        $user = Fixtures::user();
        $user->changePhoneNumber($held, false, Fixtures::now());

        // When
        $sent = $this->sender()->sendTheConfirmation($user, self::NUMBER, 'Your code is 123456.');

        // Then
        static::assertFalse($sent);
        static::assertSame([], $this->transport->sent);
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideNumbersThePersonNoLongerHolds(): iterable
    {
        yield 'no number' => [null];
        yield 'another number' => ['+33611111111'];
    }

    private function sender(): SmsSender
    {
        $transport = $this->transport;

        return new SmsSender(static fn (): TransportInterface => $transport, new NullLogger());
    }
}
