<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use App\Credential\SmsCredentialChangeChannel;
use App\Locale\Moments;
use App\Locale\UserTimeZone;
use App\Messenger\NotificationNotDeliveredException;
use App\Sms\SmsSender;
use App\Tests\Symfony\Fixture\CatalogueNotices;
use App\Tests\Symfony\Fixture\RecordingSmsTransport;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use function sprintf;
use Symfony\Component\Notifier\Transport\TransportInterface;

/**
 * Decision 0048, Decision 0049, NIST SP 800-63B-4 §4.6
 */
final class SmsCredentialChangeChannelTest extends TestCase
{
    private RecordingSmsTransport $transport;

    private User $alice;

    protected function setUp(): void
    {
        $this->transport = new RecordingSmsTransport();
        $this->alice = Fixtures::user();
        $this->alice->changePhoneNumber('+33600000000', true, Fixtures::now());
    }

    #[Test]
    public function theTextNamesTheTenantSaysWhatChangedWhatToDoIfItWasNotThePersonAndWhereTheAccountIs(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change());

        // Then
        static::assertSame(
            sprintf(
                "Acme\nA passkey was added to your account on %s. If it was not you, open your account.\nhttps://id.acme.example/account",
                $this->written(),
            ),
            $this->transport->sent[0]->getSubject(),
        );
    }

    #[Test]
    public function aPersonWithNoVerifiedNumberIsTextedNothing(): void
    {
        // Given
        $this->alice->changePhoneNumber('+33600000000', false, Fixtures::now());

        // When
        $this->channel()->tell($this->alice, $this->change());

        // Then
        static::assertSame([], $this->transport->sent);
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aTextTheTransportDidNotTakeBringsTheNoticeBack(): void
    {
        // Given
        $this->transport = new RecordingSmsTransport(refusing: true);

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIs('The SMS transport did not take the message (Symfony\Component\Notifier\Exception\TransportException).');

        // When
        $this->channel()->tell($this->alice, $this->change());
    }

    private function channel(): SmsCredentialChangeChannel
    {
        return new SmsCredentialChangeChannel(CatalogueNotices::create(), new SmsSender(fn (): TransportInterface => $this->transport, new NullLogger()));
    }

    private function change(): CredentialChange
    {
        return new CredentialChange($this->alice, CredentialEnrolled::NAME, self::moment(), 'passkey');
    }

    private function written(): string
    {
        return new Moments(new UserTimeZone())->write(self::moment(), $this->alice, 'en');
    }

    private static function moment(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-11-22T14:05:00+00:00');
    }
}
