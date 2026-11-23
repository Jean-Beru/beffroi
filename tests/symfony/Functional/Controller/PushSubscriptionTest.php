<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\NotificationsPage;
use function base64_decode;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\PushSubscriptionRepositoryInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use function strlen;
use function strtr;
use Symfony\Component\HttpFoundation\Response;

/**
 * Push API §3.4, RFC 8292 §3.2, Architecture §5.2, §5.6
 */
final class PushSubscriptionTest extends BrowserTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    private const string ENDPOINT = 'https://push.example/f/AbCdEf';

    private const string PUBLIC_KEY = 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM';

    private const string AUTH_SECRET = 'tBHItJI5svbpez7KI4CCXg';

    /**
     * RFC 8292 §3.2
     */
    #[Test]
    public function thePageHandsTheBrowserTheApplicationServerKey(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        self::applicationServerKey();

        // When
        $crawler = $this->browser->request('GET', '/account/notifications');

        // Then
        $form = $crawler->filter('form[data-push="subscribe"]');
        $key = self::string($form->attr('data-application-server-key'));
        static::assertSame(65, strlen(self::string(base64_decode(strtr($key, '-_', '+/'), true))));
        static::assertSame('/push-worker.js', $form->attr('data-worker-url'));
    }

    #[Test]
    public function aTenantWithoutAKeyHandsOutNothing(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));

        // When
        $crawler = $this->browser->request('GET', '/account/notifications');

        // Then
        static::assertSame('', $crawler->filter('form[data-push="subscribe"]')->attr('data-application-server-key'));
        static::assertStringContainsString(
            'Browser notifications are not available.',
            $crawler->filter('p[data-push-unsupported]')->text(),
        );
    }

    /**
     * Push API §8
     */
    #[Test]
    public function aBrowserThatSubscribesIsListed(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        $key = self::applicationServerKey();

        // When
        $this->subscribe();

        // Then
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT);
        static::assertInstanceOf(PushSubscription::class, $subscription);
        static::assertSame(self::PUBLIC_KEY, $subscription->publicKey);
        static::assertSame(self::AUTH_SECRET, $subscription->authSecret);
        static::assertSame($key->kid, $subscription->applicationServerKid);
        static::assertSame('Alice at the counter', $subscription->label);
    }

    #[Test]
    public function thePageListsWhatIsSubscribed(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        self::applicationServerKey();
        $this->subscribe();

        // When
        $crawler = $this->browser->request('GET', '/account/notifications');

        // Then
        static::assertCount(1, $crawler->filter('table[data-subscriptions="1"] tr[data-subscription]'));
        static::assertSame(
            ['Alice at the counter'],
            $crawler->filter('tr[data-subscription] form[data-subscription="rename"] input[name="label"]')->extract(['value']),
        );
    }

    /**
     * Push API §3.4
     */
    #[Test]
    public function aBrowserThatSubscribesAgainChangesTheRowItHas(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $first = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $this->subscribe(label: 'Alice at home');

        // Then
        $again = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('The browser is gone.');
        static::assertTrue($first->id->equals($again->id));
        static::assertEquals($first->createdAt, $again->createdAt);
        static::assertSame('Alice at home', $again->label);
        static::assertCount(1, self::subscriptions()->findActiveByUser(self::reloaded($alice)));
    }

    /**
     * RFC 8030 §7.3, Push API §3.4
     */
    #[Test]
    public function aBrowserTakenOutIsReachableAgainWhenItSubscribesAgain(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');
        $this->browser->request('POST', '/account/notifications/' . $subscription->id->toRfc4122() . '/revoke', [
            '_token' => $this->token('form[data-subscription="revoke"]'),
        ]);

        // When
        $this->subscribe();

        // Then
        static::assertCount(1, self::subscriptions()->findActiveByUser(self::reloaded($alice)));
    }

    /**
     * RFC 8030 §2
     */
    #[Test]
    public function anEndpointThatIsNotOneIsRefused(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::PASSWORD));
        self::applicationServerKey();

        // When
        $this->subscribe(endpoint: 'http://push.example/f/AbCdEf');

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="refused"]'));
    }

    /**
     * Decision 0002
     */
    #[Test]
    public function aBrowserTakenOutIsReachedByNobody(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $this->browser->request('POST', '/account/notifications/' . $subscription->id->toRfc4122() . '/revoke', [
            '_token' => $this->token('form[data-subscription="revoke"]'),
        ]);

        // Then
        static::assertSame([], self::subscriptions()->findActiveByUser(self::reloaded($alice)));
    }

    #[Test]
    public function aBrowserWithoutASessionIsToldToSignInFirst(): void
    {
        // When
        $this->browser->request('GET', '/account/notifications');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Service Workers §3.1.1
     */
    #[Test]
    public function theServiceWorkerIsServedAtTheRootOfThePages(): void
    {
        // When
        $this->browser->request('GET', '/push-worker.js');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('text/javascript; charset=utf-8', $response->headers->get('Content-Type'));
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    public function aBrowserIsNamedAgainFromTheLineItIsReadIn(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $this->rename($subscription->id->toRfc4122(), 'Alice at home');

        // Then
        static::assertSame('Alice at home', self::subscriptions()->find($subscription->id)?->label);
    }

    #[Test]
    public function aNameABrowserDoesNotHoldIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $this->rename($subscription->id->toRfc4122(), '   ');

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="invalid_label"]'));
    }

    #[Test]
    public function theBrowserOfSomebodyElseIsNotNamed(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');
        $token = $this->token('form[data-subscription="rename"]');
        $this->signIn(self::userWithPassword('grace', self::PASSWORD));

        // When
        $this->browser->request('POST', '/account/notifications/' . $subscription->id->toRfc4122() . '/name', [
            '_token' => $token,
            'label' => 'Grace at the counter',
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Push API §8
     */
    #[Test]
    public function eachRowCarriesTheDigestOfItsEndpointAndNotTheEndpoint(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $subscription = self::subscriptions()->findByEndpoint(self::reloaded($alice), self::ENDPOINT) ?? static::fail('Nothing was subscribed.');

        // When
        $crawler = $this->browser->request('GET', '/account/notifications');

        // Then
        static::assertSame([$subscription->endpointHash], $crawler->filter('tr[data-subscription]')->extract(['data-endpoint']));
        static::assertStringNotContainsString(self::ENDPOINT, self::string($this->browser->getResponse()->getContent()));
    }

    /**
     * Architecture §5.2
     */
    #[Test]
    public function theDaysOfTheLastMessageAreTheOnesRead(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        $this->signIn($alice);
        self::applicationServerKey();
        $this->subscribe();
        $this->subscribe('https://push.example/f/GhIjKl', 'Alice on the train');
        $subscriptions = self::subscriptions();
        $told = $subscriptions->findByEndpoint($alice, self::ENDPOINT) ?? static::fail('The browser is not subscribed.');
        $told->markPushed(self::currentSecond());
        $subscriptions->save($told);

        // When
        $crawler = $this->browser->request('GET', '/account/notifications', [
            NotificationsPage::PUSHED_FROM => self::currentSecond()->format('Y-m-d'),
        ]);

        // Then
        static::assertSame([(string) $told->id], $crawler->filter('tbody tr[data-subscription]')->extract(['data-subscription']));
    }

    private function rename(string $id, string $label): void
    {
        $this->browser->request('POST', '/account/notifications/' . $id . '/name', [
            '_token' => $this->token('form[data-subscription="rename"]'),
            'label' => $label,
        ]);
    }

    private function subscribe(string $endpoint = self::ENDPOINT, string $label = 'Alice at the counter'): void
    {
        $this->browser->request('POST', '/account/notifications', [
            '_token' => $this->token('form[data-push="subscribe"]'),
            'endpoint' => $endpoint,
            'p256dh' => self::PUBLIC_KEY,
            'auth' => self::AUTH_SECRET,
            'label' => $label,
        ]);
    }

    private function token(string $form): string
    {
        $crawler = $this->browser->request('GET', '/account/notifications');

        return self::string($crawler->filter($form . ' input[name="_token"]')->attr('value'));
    }

    private static function reloaded(User $user): User
    {
        self::reload();

        return self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
    }

    private static function subscriptions(): PushSubscriptionRepositoryInterface
    {
        self::reload();

        return self::service('test.beffroi.push_subscriptions', PushSubscriptionRepositoryInterface::class);
    }
}
