<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Event\NotificationChannelsChosen;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Notification\ChosenChannels;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0050, Architecture §5.2
 */
final class AccountNotificationChannelsTest extends BrowserTestCase
{
    private const array VARIABLES = ['BEFFROI_TEST_SMS_DSN'];

    protected function tearDown(): void
    {
        parent::tearDown();
        foreach (self::VARIABLES as $name) {
            unset($_SERVER[$name], $_ENV[$name]);
        }
    }

    #[Test]
    public function thePageOffersTheChannelsTheDeploymentTurnsOn(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->notificationsPage();

        // Then
        static::assertSame(['web_push', 'mail', 'sms'], $page->filter('table[data-channels] th[data-channel]')->extract(['data-channel']));
    }

    #[Test]
    public function aChannelTheDeploymentDoesNotTurnOnIsNotOffered(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_SMS_DSN'] = '';
        $this->signIn(self::user('alice'));

        // When
        $page = $this->notificationsPage();

        // Then
        static::assertSame(['web_push', 'mail'], $page->filter('table[data-channels] th[data-channel]')->extract(['data-channel']));
    }

    #[Test]
    public function aPersonWhoChoseNothingIsShownEveryChannelChecked(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->notificationsPage();

        // Then
        static::assertSame(
            [6, 0],
            [$page->filter('form[data-channels] input[type="checkbox"][checked]')->count(), $page->filter('input[name="apart[]"][checked]')->count()],
        );
    }

    /**
     * NIST SP 800-63B-4 §4.6
     */
    #[Test]
    public function aChangeOfTheCredentialsIsSaidToBeNarrowedByNoChoiceAndOffersNoBox(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->notificationsPage();

        // Then
        $row = $page->filter('tr[data-kind="credential_change"][data-every-channel]');
        static::assertSame([1, 0], [$row->count(), $row->filter('input')->count()]);
    }

    #[Test]
    public function theChannelsThePersonChoseAreKeptOnTheirAccount(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->choose(['every' => ['web_push'], 'apart' => ['pending_approval'], 'channels' => ['pending_approval' => ['sms', 'mail']]]);

        // Then
        static::assertEquals(new ChosenChannels(['web_push'], ['pending_approval' => ['mail', 'sms']]), self::reloaded($alice)->notificationChannels);
    }

    #[Test]
    public function aKindNotSetApartKeepsNoChoiceOfItsOwn(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->choose(['every' => ['mail'], 'channels' => ['pending_approval' => ['sms']]]);

        // Then
        static::assertEquals(new ChosenChannels(['mail']), self::reloaded($alice)->notificationChannels);
    }

    #[Test]
    public function aChannelTheDeploymentDoesNotOfferIsNotKept(): void
    {
        // Given
        $_SERVER['BEFFROI_TEST_SMS_DSN'] = '';
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->choose(['every' => ['sms', 'carrier_pigeon', 'mail']]);

        // Then
        static::assertEquals(new ChosenChannels(['mail']), self::reloaded($alice)->notificationChannels);
    }

    #[Test]
    public function thePageShowsTheChannelsThePersonChose(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->choose(['every' => ['web_push'], 'apart' => ['pending_approval'], 'channels' => ['pending_approval' => ['sms']]]);

        // When
        $page = $this->notificationsPage();

        // Then
        static::assertSame(
            [['web_push'], ['pending_approval'], ['sms']],
            [
                $page->filter('input[name="every[]"][checked]')->extract(['value']),
                $page->filter('input[name="apart[]"][checked]')->extract(['value']),
                $page->filter('input[name="channels[pending_approval][]"][checked]')->extract(['value']),
            ],
        );
    }

    #[Test]
    public function theChoiceIsAnActOfThePerson(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->choose(['every' => ['mail']]);

        // Then
        static::assertCount(1, self::events(NotificationChannelsChosen::class));
    }

    #[Test]
    public function theChoiceIsListedAmongTheActsOfThePerson(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->choose(['every' => ['mail']]);

        // When
        $page = $this->browser->request('GET', '/account/acts');

        // Then
        static::assertSame(['Notification channels chosen'], $page->filter('tr[data-act="notification_channels.chosen"] td')->first()->extract(['_text']));
    }

    #[Test]
    public function theChoiceIsARowOfTheHistoryOfThePersonSaidInWords(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->choose(['every' => ['mail', 'web_push']]);

        // When
        $page = $this->browser->request('GET', '/account/profile/changes');

        // Then
        $row = $page->filter('tbody tr[data-change="notification_channels"] td');
        static::assertSame(['Not chosen', 'Mail, Browsers'], [$row->eq(1)->text(), $row->eq(2)->text()]);
    }

    #[Test]
    public function theFormRefusesAForeignSubmission(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);

        // When
        $this->browser->request('POST', '/account/notifications/channels', [
            '_token' => 'forged',
            'every' => ['mail'],
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertTrue(self::reloaded($alice)->notificationChannels->isNone());
    }

    private function notificationsPage(): Crawler
    {
        $page = $this->browser->request('GET', '/account/notifications');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return $page;
    }

    /**
     * @param array<string, mixed> $chosen
     */
    private function choose(array $chosen): void
    {
        $token = self::string($this->notificationsPage()->filter('form[data-channels="choose"] input[name="_token"]')->attr('value'));
        $this->browser->request('POST', '/account/notifications/channels', ['_token' => $token, ...$chosen]);
        static::assertSame(Response::HTTP_SEE_OTHER, $this->browser->getResponse()->getStatusCode());
    }

    private static function reloaded(User $user): User
    {
        self::reload();

        return self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
    }
}
