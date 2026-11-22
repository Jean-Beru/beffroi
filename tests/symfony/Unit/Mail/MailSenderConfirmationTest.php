<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Mail;

use function array_map;
use App\Mail\MailProtection;
use App\Mail\MailSender;
use App\Mail\Smime;
use App\Tests\Symfony\Fixture\MailFixtures;
use App\Tests\Symfony\Fixture\MailProtections;
use App\Tests\Symfony\Fixture\MailSigningKeys;
use App\Tests\Symfony\Fixture\RecordingMailTransport;
use Beffroi\Core\Bridge\InMemory\InMemoryMailSigningKeyRepository;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Address;

/**
 * NIST SP 800-63B-4 §4.2.1.2, decision 0048
 */
final class MailSenderConfirmationTest extends TestCase
{
    private const string ADDRESS = 'alice@acme.example';

    private const string NOW = '2026-11-22T10:00:00+00:00';

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

    /**
     * Decision 0051
     */
    #[Test]
    public function theConfirmationToAPersonWhoAskedForEncryptedMailLeavesSignedAndNotEncrypted(): void
    {
        // Given
        $user = Fixtures::user();
        $user->changeEmail(new EmailAddress(self::ADDRESS), true, Fixtures::now());
        $user->encryptMailTo(new Smime()->read(MailFixtures::read('person-certificate.pem')), new DateTimeImmutable(self::NOW));
        $user->changeEmail(new EmailAddress(self::ADDRESS), false, Fixtures::now());
        $keys = new InMemoryMailSigningKeyRepository();
        $keys->save(MailSigningKeys::smime($user->tenant));

        // When
        $sent = $this->sender(MailProtections::over($keys, new MockClock(self::NOW)))
            ->sendTheConfirmation($user, self::ADDRESS, 'Your confirmation code', 'Your code is 123456.');

        // Then
        static::assertTrue($sent);
        $written = $this->transport->protected[0]->toString();
        static::assertStringContainsString('protocol="application/pkcs7-signature"', $written);
        static::assertStringNotContainsString('application/pkcs7-mime', $written);
        static::assertStringContainsString('Your code is 123456.', $written);
    }

    private function sender(?MailProtection $protection = null): MailSender
    {
        $transport = $this->transport;

        return new MailSender(static fn (): TransportInterface => $transport, 'Acme <no-reply@acme.example>', $protection ?? MailProtections::plain(), new NullLogger());
    }
}
