<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Fixture;

use App\Http\Timeout;
use App\Push\WebPushBroadcast;
use App\Push\WebPushSender;
use Beffroi\Core\Application\Push\PushSubscriptionRevocation;
use Beffroi\Core\Bridge\InMemory\InMemoryPushSubscriptionRepository;
use Beffroi\Core\Bridge\InMemory\InMemoryTenantKeyRepository;
use Beffroi\Core\Bridge\Key\SealedKeyProvider;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Core\Tests\Fixture\Keys;
use function array_shift;
use function is_iterable;
use function is_string;
use Psr\Log\NullLogger;
use Symfony\Component\Clock\MockClock;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\Uid\Uuid;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * The browsers of alice and the push services that reach them (RFC 8030): what those answer, in order, a 201 once
 * the answers given are spent, and every request they were sent.
 */
final class BrowsersOfAPerson
{
    public const string ENDPOINT = 'https://push.example/f/AbCdEf';

    private const string PUBLIC_KEY = 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtUbVlUls0VJXg7A8u-Ts1XbjhazAkj7I99e8QcYP7DkM';

    private const string AUTH_SECRET = 'tBHItJI5svbpez7KI4CCXg';

    public readonly Tenant $tenant;

    public readonly User $alice;

    public readonly MockClock $clock;

    public readonly InMemoryPushSubscriptionRepository $subscriptions;

    /**
     * @var list<MockResponse>
     */
    public private(set) array $requests = [];

    /**
     * @var list<MockResponse>
     */
    private array $answers = [];

    private readonly InMemoryTenantKeyRepository $keys;

    public function __construct()
    {
        $this->tenant = Fixtures::tenant();
        $this->alice = Fixtures::user($this->tenant);
        $this->clock = new MockClock('2026-09-28T09:00:00+00:00');
        $this->subscriptions = new InMemoryPushSubscriptionRepository();
        $this->keys = new InMemoryTenantKeyRepository();
        $this->keys->save($this->activeKey());
    }

    /**
     * @param list<int> $statuses what the push services answer, one status a request
     */
    public function answering(array $statuses): self
    {
        foreach ($statuses as $status) {
            $this->answers[] = new MockResponse('', [
                'http_code' => $status,
            ]);
        }

        return $this;
    }

    public function subscribed(string $endpoint = self::ENDPOINT): PushSubscription
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

    public function broadcast(): WebPushBroadcast
    {
        $http = new MockHttpClient(function (): ResponseInterface {
            $answer = array_shift($this->answers) ?? new MockResponse('', [
                'http_code' => 201,
            ]);
            $this->requests[] = $answer;

            return $answer;
        });

        return new WebPushBroadcast(
            $this->subscriptions,
            new PushSubscriptionRevocation($this->subscriptions, $this->clock),
            new WebPushSender(
                new SealedKeyProvider($this->keys, Keys::opened()),
                $http,
                $this->clock,
                'mailto:operator@acme.example',
                new Timeout(1.0),
            ),
            $this->clock,
            new NullLogger(),
        );
    }

    /**
     * @return list<string> the header lines of the request sent at that rank
     */
    public function headersOf(int $rank): array
    {
        $headers = $this->requests[$rank]->getRequestOptions()['headers'] ?? [];
        $lines = [];
        foreach (is_iterable($headers) ? $headers : [] as $line) {
            if (is_string($line)) {
                $lines[] = $line;
            }
        }

        return $lines;
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

        return $key;
    }
}
