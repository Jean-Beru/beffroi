<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Ciba;

use function array_map;
use function array_values;
use function base64_encode;
use function count;
use App\Message\TellUserOfPendingApproval;
use App\MessageHandler\TellUserOfPendingApprovalHandler;
use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\EventListener\MessageLoggerListener;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Transport\TransportInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Notifier\EventListener\NotificationLoggerListener;
use Symfony\Component\Notifier\Message\MessageInterface;

/**
 * Decision 0048, CIBA Core §7, Architecture §5.6
 */
final class PendingApprovalByMailAndSmsTest extends BrowserTestCase
{
    private const string ADDRESS = 'alice@op.test';

    private const string NUMBER = '+33600000000';

    private const array VARIABLES = ['BEFFROI_TEST_MAIL_SENDER', 'BEFFROI_TEST_SMS_DSN'];

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $name) {
            unset($_SERVER[$name], $_ENV[$name]);
        }
    }

    #[Test]
    public function aPendingApprovalIsWrittenToTheAddressThePersonVerified(): void
    {
        // Given
        $this->alice(verified: true);
        $this->ask();

        // When
        self::deliverQueued();

        // Then
        $mails = self::mails();
        static::assertCount(1, $mails);
        static::assertSame([self::ADDRESS], array_map(static fn (Address $address): string => $address->getAddress(), $mails[0]->getTo()));
        static::assertSame(['no-reply@op.test'], array_map(static fn (Address $address): string => $address->getAddress(), $mails[0]->getFrom()));
    }

    #[Test]
    public function aPendingApprovalIsTextedToTheNumberThePersonVerified(): void
    {
        // Given
        $this->alice(verified: true);
        $this->ask();

        // When
        self::deliverQueued();

        // Then
        static::assertSame([self::NUMBER], array_map(static fn (MessageInterface $text): ?string => $text->getRecipientId(), self::texts()));
    }

    #[Test]
    public function anAddressAndANumberNobodyVerifiedAreSentNothing(): void
    {
        // Given
        $this->alice(verified: false);
        $this->ask();

        // When
        self::deliverQueued();

        // Then
        static::assertSame([[], []], [self::mails(), self::texts()]);
    }

    /**
     * Decision 0050
     */
    #[Test]
    public function aPendingApprovalReachesThePersonByTheChannelsTheyChoseAlone(): void
    {
        // Given
        $this->alice(verified: true, chosen: new ChosenChannels(['mail'], ['pending_approval' => ['sms']]));
        $this->ask();

        // When
        self::deliverQueued();

        // Then
        static::assertSame([0, 1], [count(self::mails()), count(self::texts())]);
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aMailDsnWithoutASenderLeavesTheTextToTellThePerson(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_MAIL_SENDER'] = '';
        $this->alice(verified: true);
        $this->ask();

        // When
        self::deliverQueued();

        // Then
        static::assertSame([0, 1], [count(self::mails()), count(self::texts())]);
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function anSmsDsnNoInstalledBridgeReadsLeavesTheMailToTellThePerson(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_SMS_DSN'] = 'example://default';
        $this->alice(verified: true);
        $this->ask();

        // When
        self::deliverQueued();

        // Then
        static::assertSame([1, 0], [count(self::mails()), count(self::texts())]);
    }

    /**
     * CIBA Core §7.3
     */
    #[Test]
    public function theMailCarriesNotTheIdentifierOfTheRequest(): void
    {
        // Given
        $this->alice(verified: true);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);

        // When
        self::deliverQueued();

        // Then
        static::assertStringNotContainsString($authRequestId, self::string(self::mails()[0]->getTextBody()));
    }

    /**
     * CIBA Core §7.3
     */
    #[Test]
    public function theTextCarriesNotTheIdentifierOfTheRequest(): void
    {
        // Given
        $this->alice(verified: true);
        $authRequestId = self::string(self::json($this->ask())['auth_req_id']);

        // When
        self::deliverQueued();

        // Then
        static::assertStringNotContainsString($authRequestId, self::texts()[0]->getSubject());
    }

    private function alice(bool $verified, ?ChosenChannels $chosen = null): void
    {
        $alice = self::userWithPassword('alice', 'correct horse battery staple');
        $alice->changeEmail(new EmailAddress(self::ADDRESS), $verified, self::now());
        $alice->changePhoneNumber(self::NUMBER, $verified, self::now());
        $alice->chooseChannels($chosen ?? ChosenChannels::none(), self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);
    }

    private function ask(): Response
    {
        self::signingKey();
        $this->browser->request(
            'POST',
            '/backchannel_authentication',
            [
                'scope' => 'openid profile',
                'login_hint' => 'alice-subject',
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('terminal-app:terminal-secret-of-at-least-32-characters'),
            ],
        );

        return $this->browser->getResponse();
    }

    /**
     * As the worker of the lane hands each message to its handler.
     */
    private static function deliverQueued(): void
    {
        $handler = self::service('test.beffroi.pending_approval_delivery', TellUserOfPendingApprovalHandler::class);
        foreach (self::service('test.beffroi.notification_queue', TransportInterface::class)->get() as $envelope) {
            static::assertInstanceOf(Envelope::class, $envelope);
            $message = $envelope->getMessage();
            static::assertInstanceOf(TellUserOfPendingApproval::class, $message);
            $handler($message);
        }
    }

    /**
     * @return list<Email>
     */
    private static function mails(): array
    {
        $mails = [];
        foreach (self::service('test.beffroi.mails', MessageLoggerListener::class)->getEvents()->getMessages() as $mail) {
            static::assertInstanceOf(Email::class, $mail);
            $mails[] = $mail;
        }

        return $mails;
    }

    /**
     * @return list<MessageInterface>
     */
    private static function texts(): array
    {
        return array_values(self::service('test.beffroi.texts', NotificationLoggerListener::class)->getEvents()->getMessages());
    }
}
