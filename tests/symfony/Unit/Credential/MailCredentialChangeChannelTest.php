<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Credential;

use App\Credential\MailCredentialChangeChannel;
use App\Locale\Moments;
use App\Locale\UserTimeZone;
use App\Mail\MailSender;
use App\Messenger\NotificationNotDeliveredException;
use App\Tests\Symfony\Fixture\CatalogueNotices;
use App\Tests\Symfony\Fixture\MailProtections;
use App\Tests\Symfony\Fixture\RecordingMailTransport;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Tests\Fixture\Fixtures;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use function sprintf;
use Symfony\Component\Mailer\Transport\TransportInterface;

/**
 * Decision 0048, Decision 0049, NIST SP 800-63B-4 §4.6
 */
final class MailCredentialChangeChannelTest extends TestCase
{
    private RecordingMailTransport $transport;

    private User $alice;

    protected function setUp(): void
    {
        $this->transport = new RecordingMailTransport();
        $this->alice = Fixtures::user();
        $this->alice->changeEmail(new EmailAddress('alice@acme.example'), true, Fixtures::now());
    }

    #[Test]
    public function theSubjectNamesTheTenantAndSaysHowThePersonSignsInChanged(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change());

        // Then
        static::assertSame('Acme: a change to how you sign in', $this->transport->sent[0]->getSubject());
    }

    #[Test]
    public function theMailSaysWhatChangedWhatToDoIfItWasNotThePersonAndWhereTheAccountIs(): void
    {
        // When
        $this->channel()->tell($this->alice, $this->change());

        // Then
        static::assertSame(
            sprintf("A passkey was added to your account on %s. If it was not you, open your account.\n\nhttps://id.acme.example/account\n", $this->written()),
            $this->transport->sent[0]->getTextBody(),
        );
    }

    /**
     * Architecture §5.7, OIDC Core §5.1
     */
    #[Test]
    public function theMailIsWrittenOnTheClockOfThePerson(): void
    {
        // Given
        $this->alice->updateProfile(new Profile(zoneinfo: 'Europe/Paris', locale: 'fr'), Fixtures::now());

        // When
        $this->channel()->tell($this->alice, $this->change());

        // Then
        static::assertSame(
            "Une passkey a été ajoutée à votre compte le 22 nov. 2026, 15:05 UTC+1. Si ce n'était pas vous, ouvrez votre compte.\n\nhttps://id.acme.example/account\n",
            $this->transport->sent[0]->getTextBody(),
        );
    }

    #[Test]
    public function aPersonWithNoVerifiedAddressIsWrittenNothing(): void
    {
        // Given
        $this->alice->changeEmail(new EmailAddress('alice@acme.example'), false, Fixtures::now());

        // When
        $this->channel()->tell($this->alice, $this->change());

        // Then
        static::assertSame([], $this->transport->sent);
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aMailTheTransportDidNotTakeBringsTheNoticeBack(): void
    {
        // Given
        $this->transport = new RecordingMailTransport(refusing: true);

        // Then
        $this->expectException(NotificationNotDeliveredException::class);
        $this->expectExceptionMessageIs('The mail transport did not take the message (Symfony\Component\Mailer\Exception\TransportException, code 450).');

        // When
        $this->channel()->tell($this->alice, $this->change());
    }

    private function channel(): MailCredentialChangeChannel
    {
        return new MailCredentialChangeChannel(
            CatalogueNotices::create(),
            new MailSender(fn (): TransportInterface => $this->transport, 'no-reply@acme.example', MailProtections::plain(), new NullLogger()),
        );
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
