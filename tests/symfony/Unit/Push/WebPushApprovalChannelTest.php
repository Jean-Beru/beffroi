<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Push;

use Heidi\Bundle\Ciba\WebPushApprovalChannel;
use Heidi\Bundle\Push\WebPushSender;
use Heidi\Core\Application\Push\PushSubscriptionRevocation;
use Heidi\Core\Bridge\InMemory\InMemoryPushSubscriptionRepository;
use Heidi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Heidi\Core\Bridge\Key\SealedKeyProvider;
use Heidi\Core\Domain\Identity\PushSubscription;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Domain\Key\TenantKey;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Core\Tests\Fixture\Algorithms;
use Heidi\Core\Tests\Fixture\Fixtures;
use Heidi\Core\Tests\Fixture\Keys;
use Heidi\Oidc\Domain\Ciba\BindingMessage;
use Heidi\Oidc\Domain\Ciba\PendingApproval;
use function array_shift;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Messenger\Exception\RecoverableMessageHandlingException;
use Symfony\Component\Uid\Uuid;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * RFC 8030, RFC 8291, RFC 8292, BCP 10027 §5.2: what the browsers of a user are told when a client asks
 * for something only that user can answer, and what becomes of a browser that is not there any more.
 */
final class WebPushApprovalChannelTest extends TestCase
{
    private const string ENDPOINT = 'https://push.example/f/AbCdEf';

    private const string PUBLIC_KEY = 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM';

    private const string AUTH_SECRET = 'tBHItJI5svbpez7KI4CCXg';

    private Tenant $tenant;

    private User $alice;

    private MockClock $clock;

    private InMemoryPushSubscriptionRepository $subscriptions;

    private InMemoryTenantKeyRepository $keys;

    /**
     * @var list<MockResponse>
     */
    private array $requests = [];

    protected function setUp(): void
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->clock = new MockClock('2026-09-28T09:00:00+00:00');
        $this->subscriptions = new InMemoryPushSubscriptionRepository();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->activeKey();
    }

    /**
     * A deployment that reaches nobody is not a deployment that fails: the user finds the request on the
     * page where requests are answered.
     */
    #[Test]
    public function aUserWithNoBrowserIsToldNothingAndNothingFails(): void
    {
        // Given
        $channel = $this->channel(new MockResponse('', [
            'http_code' => 500,
        ]));

        // When
        $channel->tell($this->alice, $this->approval());

        // Then
        static::assertSame([], $this->requests);
    }

    /**
     * BCP 10027 §5.2: what a browser is told is who is asking, what they wrote and where an answer is
     * given; nothing of it names the request or answers it.
     */
    #[Test]
    public function aBrowserIsToldWhoIsAskingAndWhereToAnswer(): void
    {
        // Given
        $this->subscribed();
        $channel = $this->channel(new MockResponse('', [
            'http_code' => 201,
        ]));

        // When
        $channel->tell($this->alice, $this->approval());

        // Then
        static::assertCount(1, $this->requests);
        static::assertSame(self::ENDPOINT, $this->requests[0]->getRequestUrl());
        static::assertNotNull($this->subscriptions->findActiveByUser($this->alice)[0]->lastPushedAt);
    }

    /**
     * RFC 8030 §5.2: a message worth nothing once the request has expired is not one a push service
     * should keep for a device that is asleep.
     */
    #[Test]
    public function theMessageIsWorthDeliveringAsLongAsTheRequestIs(): void
    {
        // Given
        $this->subscribed();
        $channel = $this->channel(new MockResponse('', [
            'http_code' => 201,
        ]));

        // When
        $channel->tell($this->alice, $this->approval());

        // Then
        $headers = $this->requests[0]->getRequestOptions()['headers'] ?? null;
        static::assertIsIterable($headers);
        static::assertContains('TTL: 300', $headers);
    }

    /**
     * RFC 8030 §7.3: a push service that says the subscription is gone has taken the browser out, and
     * the row follows rather than being tried for ever.
     */
    #[Test]
    public function aBrowserThePushServiceSaysIsGoneIsTakenOut(): void
    {
        // Given
        $this->subscribed();
        $channel = $this->channel(new MockResponse('', [
            'http_code' => 410,
        ]));

        // When
        $channel->tell($this->alice, $this->approval());

        // Then
        static::assertSame([], $this->subscriptions->findActiveByUser($this->alice));
    }

    /**
     * Architecture §5.6: a push service that did not answer may answer in a minute, and the lane is what
     * comes back, as it does for a logout token.
     */
    #[Test]
    public function aPushServiceThatDidNotAnswerBringsTheLaneBack(): void
    {
        // Given
        $this->subscribed();
        $channel = $this->channel(new MockResponse('', [
            'http_code' => 503,
        ]));

        // Then
        $this->expectException(RecoverableMessageHandlingException::class);
        $this->expectExceptionMessageIsOrContains('No browser of this user was reached');

        // When
        $channel->tell($this->alice, $this->approval());
    }

    /**
     * One browser that got it is a user who was told: the lane is not brought back for the others.
     */
    #[Test]
    public function oneBrowserReachedIsEnough(): void
    {
        // Given
        $this->subscribed();
        $this->subscribed('https://push.example/f/Other');
        $channel = $this->channel(
            new MockResponse('', [
                'http_code' => 503,
            ]),
            new MockResponse('', [
                'http_code' => 201,
            ]),
        );

        // When
        $channel->tell($this->alice, $this->approval());

        // Then
        static::assertCount(2, $this->requests);
    }

    private function channel(MockResponse ...$responses): WebPushApprovalChannel
    {
        $http = new MockHttpClient(function (string $method, string $url, array $options) use (&$responses): ResponseInterface {
            $response = array_shift($responses) ?? new MockResponse('', [
                'http_code' => 201,
            ]);
            $this->requests[] = $response;

            return $response;
        });

        return new WebPushApprovalChannel(
            $this->subscriptions,
            new PushSubscriptionRevocation($this->subscriptions, $this->clock),
            new WebPushSender(
                new SealedKeyProvider($this->keys, Keys::sealer()),
                $http,
                $this->clock,
                'mailto:operator@acme.example',
                1.0,
            ),
            $this->translator(),
            $this->clock,
            new NullLogger(),
        );
    }

    private function translator(): TranslatorInterface
    {
        $translator = self::createStub(TranslatorInterface::class);
        $translator->method('trans')->willReturnArgument(0);

        return $translator;
    }

    private function approval(): PendingApproval
    {
        return new PendingApproval(
            $this->tenant,
            $this->alice->id,
            'Payment terminal at the counter',
            new BindingMessage('Payment of 42 euros'),
            $this->clock->now()->modify('+300 seconds'),
            'https://id.acme.example/approvals',
        );
    }

    private function subscribed(string $endpoint = self::ENDPOINT): PushSubscription
    {
        $subscription = new PushSubscription(
            Uuid::v7(),
            $this->alice,
            $endpoint,
            self::PUBLIC_KEY,
            self::AUTH_SECRET,
            Keys::applicationServerPair()->kid,
            'Alice at the counter',
            $this->clock->now(),
        );
        $this->subscriptions->save($subscription);

        return $subscription;
    }

    private function activeKey(): TenantKey
    {
        $pair = Keys::applicationServerPair();
        $key = new TenantKey(
            $pair->kid,
            $this->tenant,
            Algorithms::vapid(),
            $pair->publicJwk,
            Keys::sealer()->seal($this->tenant, $pair->privateJwk),
            $this->clock->now(),
            $this->clock->now(),
        );
        $key->activate($this->clock->now());
        $this->keys->save($key);

        return $key;
    }
}
