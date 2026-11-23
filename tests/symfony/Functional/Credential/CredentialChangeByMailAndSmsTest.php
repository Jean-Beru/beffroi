<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Credential;

use function array_map;
use function array_values;
use App\Message\TellUserOfCredentialChange;
use App\Messenger\NotificationRetryPolicy;
use App\Tests\Symfony\Functional\Command\ConsoleTestCase;
use App\Messenger\RetrySchedule;
use Beffroi\Core\Domain\Credential\CredentialChange;
use Beffroi\Core\Domain\Event\CredentialChangeNotTold;
use Beffroi\Core\Domain\Event\CredentialEnrolled;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\ActsOfAPersonInterface;
use Beffroi\Core\Port\CredentialChangeNotifierInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Closure;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Mailer\EventListener\MessageLoggerListener;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Notifier\EventListener\NotificationLoggerListener;
use Symfony\Component\Notifier\Message\MessageInterface;

/**
 * Decision 0048, Decision 0049, NIST SP 800-63B-4 §4.6, Architecture §5.6
 */
final class CredentialChangeByMailAndSmsTest extends ConsoleTestCase
{
    private const string ADDRESS = 'alice@op.test';

    private const string NUMBER = '+33600000000';

    /**
     * Nothing listens there: every mail is refused at the connection, as by a server that is down.
     */
    private const string UNREACHABLE_MAIL_DSN = 'smtp://127.0.0.1:1';

    /**
     * A bridge the application installs, whose provider answers 503 to every text (configureContainer()).
     */
    private const string UNAVAILABLE_SMS_DSN = 'sweego://key@default?region=FR&campaign_type=transac&shorten_urls=false';

    private const array VARIABLES = ['BEFFROI_TEST_MAIL_DSN', 'BEFFROI_TEST_SMS_DSN'];

    protected function configureContainer(): Closure
    {
        return static function (ContainerInterface $container): void {
            $container->set(
                'http_client',
                new MockHttpClient(
                    static fn (): MockResponse => new MockResponse('', [
                        'http_code' => 503,
                    ]),
                ),
            );
        };
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $name) {
            unset($_SERVER[$name], $_ENV[$name]);
        }
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function eachChannelHasANoticeOfItsOwnOnTheLaneAfterWebPush(): void
    {
        // When
        self::tell(self::alice(verified: true));

        // Then
        static::assertSame(
            ['web_push', 'mail', 'sms'],
            array_map(static fn (Envelope $envelope): string => self::notice($envelope)->channel, self::queued()),
        );
    }

    #[Test]
    public function aChangeIsWrittenToTheAddressThePersonVerified(): void
    {
        // Given
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        $mails = self::mails();
        static::assertCount(1, $mails);
        static::assertSame([self::ADDRESS], array_map(static fn (Address $address): string => $address->getAddress(), $mails[0]->getTo()));
    }

    #[Test]
    public function aChangeIsTextedToTheNumberThePersonVerified(): void
    {
        // Given
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        static::assertSame([self::NUMBER], array_map(static fn (MessageInterface $text): ?string => $text->getRecipientId(), self::texts()));
    }

    #[Test]
    public function anAddressAndANumberNobodyVerifiedAreSentNothing(): void
    {
        // Given
        self::tell(self::alice(verified: false));

        // When
        self::work();

        // Then
        static::assertSame([[], []], [self::mails(), self::texts()]);
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function aMailThatIsNeverTakenLeavesTheTextToTellThePerson(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_MAIL_DSN'] = self::UNREACHABLE_MAIL_DSN;
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        static::assertCount(1, self::texts());
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aMailThatIsNotTakenIsWrittenAgainAsOftenAsTheScheduleOfTheNoticesAllows(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_MAIL_DSN'] = self::UNREACHABLE_MAIL_DSN;
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        static::assertCount(self::notices()->attempts(), self::mails());
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function aMailThatIsNeverTakenIsAnActOfThePersonOnceTheScheduleIsSpent(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_MAIL_DSN'] = self::UNREACHABLE_MAIL_DSN;
        $alice = self::alice(verified: true);
        self::tell($alice);

        // When
        self::work();

        // Then
        static::assertCount(1, self::service('test.beffroi.acts', ActsOfAPersonInterface::class)->lastOf($alice, [CredentialChangeNotTold::NAME], 10));
    }

    #[Test]
    public function aNoticeThatReachesThePersonIsNoAct(): void
    {
        // Given
        $alice = self::alice(verified: true);
        self::tell($alice);

        // When
        self::work();

        // Then
        static::assertSame([], self::service('test.beffroi.acts', ActsOfAPersonInterface::class)->lastOf($alice, [CredentialChangeNotTold::NAME], 10));
    }

    /**
     * Architecture §5.6
     */
    #[Test]
    public function aTextThatIsNotTakenDoesNotWriteTheMailAgain(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_SMS_DSN'] = self::UNAVAILABLE_SMS_DSN;
        self::tell(self::alice(verified: true));

        // When
        self::work();

        // Then
        static::assertCount(1, self::mails());
    }

    private static function alice(bool $verified): User
    {
        $alice = self::user();
        $alice->changeEmail(new EmailAddress(self::ADDRESS), $verified, self::now());
        $alice->changePhoneNumber(self::NUMBER, $verified, self::now());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);

        return $alice;
    }

    private static function tell(User $user): void
    {
        self::service('test.beffroi.credential_change_notifier', CredentialChangeNotifierInterface::class)
            ->tell(
                new CredentialChange($user, CredentialEnrolled::NAME, self::now(), 'passkey'),
            );
    }

    /**
     * The worker of the lane, under the mocked clock, for as long as its policy keeps a message coming back.
     */
    private static function work(): void
    {
        self::mockTime();
        self::console('messenger:consume', [
            'receivers' => ['async_notifications'],
            '--time-limit' => (string) (2 * self::notices()->waiting()),
            '--no-reset' => null,
        ]);
    }

    private static function notice(Envelope $envelope): TellUserOfCredentialChange
    {
        $message = $envelope->getMessage();
        static::assertInstanceOf(TellUserOfCredentialChange::class, $message);

        return $message;
    }

    private static function notices(): RetrySchedule
    {
        return self::service(NotificationRetryPolicy::class, NotificationRetryPolicy::class)->notices;
    }

    /**
     * Each mail handed to the transport, taken or not.
     *
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
     * Each text handed to the transport, taken or not.
     *
     * @return list<MessageInterface>
     */
    private static function texts(): array
    {
        return array_values(self::service('test.beffroi.texts', NotificationLoggerListener::class)->getEvents()->getMessages());
    }
}
