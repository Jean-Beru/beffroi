<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use function array_map;
use App\Mail\MailSender;
use App\Messenger\NotificationNotDeliveredException;
use App\Tests\Symfony\Fixture\RecordingMailTransport;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Mailer\Exception\UnsupportedSchemeException;
use Symfony\Component\Mailer\Transport\Dsn;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Address;

/**
 * Decision 0048
 */
final class MailSenderTest extends TestCase
{
    private const string ADDRESS = 'alice@acme.example';

    private RecordingMailTransport $transport;

    protected function setUp(): void
    {
        $this->transport = new RecordingMailTransport();
    }

    #[Test]
    public function aPersonIsWrittenToAtTheAddressMarkedVerified(): void
    {
        // When
        $sent = $this->sender()->send(self::verified(), 'A sign-in is waiting', 'Open your account to answer.');

        // Then
        static::assertTrue($sent);
        static::assertCount(1, $this->transport->sent);
        $mail = $this->transport->sent[0];
        static::assertSame([self::ADDRESS], array_map(static fn (Address $address): string => $address->getAddress(), $mail->getTo()));
        static::assertSame('A sign-in is waiting', $mail->getSubject());
        static::assertSame('Open your account to answer.', $mail->getTextBody());
    }

    #[Test]
    public function theMailIsWrittenFromTheSenderOfTheDeployment(): void
    {
        // When
        $this->sender()->send(self::verified(), 'A sign-in is waiting', 'Open your account to answer.');

        // Then
        static::assertSame(
            ['"Acme" <no-reply@acme.example>'],
            array_map(static fn (Address $address): string => $address->toString(), $this->transport->sent[0]->getFrom()),
        );
    }

    /**
     * RFC 3834 §5.2
     */
    #[Test]
    public function theMailSaysAProcessWroteIt(): void
    {
        // When
        $this->sender()->send(self::verified(), 'A sign-in is waiting', 'Open your account to answer.');

        // Then
        static::assertSame('auto-generated', $this->transport->sent[0]->getHeaders()->getHeaderBody('Auto-Submitted'));
    }

    #[Test]
    #[DataProvider('provideAddressesNobodyVerified')]
    public function aPersonWhoseAddressNobodyVerifiedIsWrittenNothing(?EmailAddress $address): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail($address, false, Fixtures::now());

        // When
        $sent = $this->sender()->send($user, 'A sign-in is waiting', 'Open your account to answer.');

        // Then
        static::assertFalse($sent);
        static::assertSame([], $this->transport->sent);
    }

    /**
     * @return iterable<string, array{?EmailAddress}>
     */
    public static function provideAddressesNobodyVerified(): iterable
    {
        yield 'no address' => [null];
        yield 'an address nobody verified' => [new EmailAddress(self::ADDRESS)];
    }

    /**
     * RFC 5322 §3.4.1
     */
    #[Test]
    public function aVerifiedAddressTheMailCannotCarryIsWrittenNothing(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress('very.unusual."@".unusual.com@example.com'), true, Fixtures::now());

        // When
        $sent = $this->sender()->send($user, 'A sign-in is waiting', 'Open your account to answer.');

        // Then
        static::assertFalse($sent);
        static::assertSame([], $this->transport->sent);
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aTransportThatDidNotTakeTheMailBringsTheLaneBack(): void
    {
        // Given
        $sender = $this->sender(new RecordingMailTransport(refusing: true));

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIs('The mail transport did not take the message (Symfony\Component\Mailer\Exception\TransportException, code 450).');

        // When
        $sender->send(self::verified(), 'A sign-in is waiting', 'Open your account to answer.');
    }

    /**
     * Decision 0011
     */
    #[Test]
    public function theFailureLeavesOutWhatTheServerSaidOfTheAddress(): void
    {
        // Given
        $sender = $this->sender(new RecordingMailTransport(refusing: true));

        // When
        try {
            $sender->send(self::verified(), 'A sign-in is waiting', 'Open your account to answer.');
            static::fail('The transport took the mail.');
        } catch (NotificationNotDeliveredException $failure) {
            // Then
            static::assertStringNotContainsString(self::ADDRESS, $failure->getMessage());
        }
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    #[DataProvider('provideSendersThatAreNoAddress')]
    public function aSenderThatIsNoAddressWritesNothing(?string $address): void
    {
        // Given
        $sender = new MailSender(fn (): TransportInterface => $this->transport, $address, new NullLogger());

        // When
        $sent = $sender->send(self::verified(), 'A sign-in is waiting', 'Open your account to answer.');

        // Then
        static::assertFalse($sent);
        static::assertSame([], $this->transport->sent);
    }

    /**
     * @return iterable<string, array{?string}>
     */
    public static function provideSendersThatAreNoAddress(): iterable
    {
        yield 'none' => [null];
        yield 'a name alone' => ['the operator'];
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aDsnNoInstalledFactoryReadsWritesNothing(): void
    {
        // Given
        $sender = new MailSender(
            static fn (): TransportInterface => throw new UnsupportedSchemeException(new Dsn('example+api', 'default')),
            'no-reply@acme.example',
            new NullLogger(),
        );

        // When
        $sent = $sender->send(self::verified(), 'A sign-in is waiting', 'Open your account to answer.');

        // Then
        static::assertFalse($sent);
    }

    private function sender(?RecordingMailTransport $transport = null): MailSender
    {
        $transport ??= $this->transport;

        return new MailSender(static fn (): TransportInterface => $transport, 'Acme <no-reply@acme.example>', new NullLogger());
    }

    private static function verified(): User
    {
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress(self::ADDRESS), true, Fixtures::now());

        return $user;
    }
}
