<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use function array_map;
use App\Mail\MailSender;
use App\Tests\Symfony\Fixture\RecordingMailTransport;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Address;

/**
 * NIST SP 800-63B-4 §4.2.1.2, decision 0048
 */
final class MailSenderConfirmationTest extends TestCase
{
    private const string ADDRESS = 'alice@acme.example';

    private RecordingMailTransport $transport;

    protected function setUp(): void
    {
        $this->transport = new RecordingMailTransport();
    }

    #[Test]
    #[DataProvider('provideVerifications')]
    public function theConfirmationIsWrittenToTheAddressItEstablishesWhateverItsVerification(bool $verified): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress(self::ADDRESS), $verified, Fixtures::now());

        // When
        $sent = $this->sender()->sendTheConfirmation($user, self::ADDRESS, 'Your confirmation code', 'Your code is 123456.');

        // Then
        static::assertTrue($sent);
        static::assertSame([self::ADDRESS], array_map(static fn (Address $address): string => $address->getAddress(), $this->transport->sent[0]->getTo()));
    }

    /**
     * @return iterable<string, array{bool}>
     */
    public static function provideVerifications(): iterable
    {
        yield 'an address nobody verified yet' => [false];
        yield 'an address verified meanwhile' => [true];
    }

    #[Test]
    #[DataProvider('provideAddressesThePersonNoLongerHolds')]
    public function theConfirmationOfAnAddressThePersonNoLongerHoldsIsWrittenNothing(?EmailAddress $held): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail($held, false, Fixtures::now());

        // When
        $sent = $this->sender()->sendTheConfirmation($user, self::ADDRESS, 'Your confirmation code', 'Your code is 123456.');

        // Then
        static::assertFalse($sent);
        static::assertSame([], $this->transport->sent);
    }

    /**
     * @return iterable<string, array{?EmailAddress}>
     */
    public static function provideAddressesThePersonNoLongerHolds(): iterable
    {
        yield 'no address' => [null];
        yield 'another address' => [new EmailAddress('alice@elsewhere.example')];
    }

    /**
     * RFC 3834 §5.2
     */
    #[Test]
    public function theConfirmationSaysAProcessWroteIt(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress(self::ADDRESS), false, Fixtures::now());

        // When
        $this->sender()->sendTheConfirmation($user, self::ADDRESS, 'Your confirmation code', 'Your code is 123456.');

        // Then
        static::assertSame('auto-generated', $this->transport->sent[0]->getHeaders()->getHeaderBody('Auto-Submitted'));
    }

    private function sender(): MailSender
    {
        $transport = $this->transport;

        return new MailSender(static fn (): TransportInterface => $transport, 'Acme <no-reply@acme.example>', new NullLogger());
    }
}
