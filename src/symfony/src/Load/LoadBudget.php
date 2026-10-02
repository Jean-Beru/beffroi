<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Load;

use DateInterval;
use Beffroi\Core\Exception\LoadBudgetSpentException;
use function max;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\RateLimiter\Storage\StorageInterface;
use function time;

/**
 * A budget that bounds a load (decision 0014): a name, a number of requests, a window, and the store
 * the count is kept in. It counts one request on a key and refuses the one that finds the window full;
 * what the key stands for is the caller's, the origin of a request or the client that authenticated.
 *
 * A sliding window, as the attempts of a user are counted (`RateLimitedAttempts`): a caller that spends
 * a whole minute of budget in a second waits the window out rather than being served again at the top
 * of the next one. The numbers are the deployment's and the window is this class's; the policy is not
 * configurable, because a budget that forgets at a fixed hour is a budget with a hole in it.
 */
final readonly class LoadBudget
{
    /**
     * The budget of the origin of a request, counted before anything is verified.
     */
    public const string ORIGIN = 'origin';

    /**
     * The budget of a client that authenticated, counted where its identifier is proven.
     */
    public const string CLIENT = 'client';

    private RateLimiterFactoryInterface $limiter;

    public function __construct(
        public string $name,
        int $limit,
        DateInterval $interval,
        StorageInterface $storage,
    ) {
        $this->limiter = new RateLimiterFactory([
            'id' => 'beffroi_' . $name . '_load',
            'policy' => 'sliding_window',
            'limit' => $limit,
            'interval' => $interval,
        ], $storage);
    }

    /**
     * Counts one request on the key, and refuses the request that finds no room left.
     *
     * The delay handed back is the one the limiter computes, read against the clock the limiter counts
     * with, which is the clock of the machine and not the one the provider dates its facts with
     * (Symfony's own RateLimitAttributeListener does the same). Never zero: a delay of no seconds
     * invites the retry that is refused again.
     *
     * @param string $key what the budget is counted on, which a caller must not be able to choose for
     *                    somebody else
     * @param string|null $client the client the budget was counted on, for the audit trail
     *
     * @throws LoadBudgetSpentException
     */
    public function consume(string $key, ?string $client = null): void
    {
        $limit = $this->limiter->create($key)->consume();
        if ($limit->isAccepted()) {
            return;
        }

        throw new LoadBudgetSpentException($this->name, max(1, $limit->getRetryAfter()->getTimestamp() - time()), $client);
    }
}
