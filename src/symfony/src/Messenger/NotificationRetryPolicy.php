<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Messenger;

use Beffroi\Bundle\Configuration\BoundedNumber;
use function min;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Retry\RetryStrategyInterface;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;
use Throwable;

/**
 * How long the provider goes on trying to hand a notification to the third party it is addressed to
 * (architecture §5.6): a send that did not reach its client comes back a fixed number of times, waiting
 * longer at each one up to a ceiling, and a relying party that is restarting is therefore tried again
 * for longer than a write of our own would be. The application routes its notifications to a transport
 * this policy drives (apps/op/config/packages/messenger.yaml), and the retirement of a signing key reads
 * the same object to know how long a logout token may still be on its way (issue #155): one schedule,
 * two readers, so that the two cannot disagree.
 *
 * The waits are exact, where Symfony's own strategy scatters them by a tenth: a session announces itself
 * to the handful of clients it signed in and not to a fleet, and what a retirement window covers is a
 * number, not a distribution.
 */
final readonly class NotificationRetryPolicy implements RetryStrategyInterface
{
    /**
     * The four numbers are those of "beffroi.back_channel_logout" (BackChannelLogoutSection), held here to the floors
     * the tree holds them to, which is where a number an environment variable carries is first a number.
     *
     * @throws InvalidConfigurationException when a number is below the floor of its node
     */
    public function __construct(
        public int $retries = 6,
        public int $delay = 2,
        public int $multiplier = 3,
        public int $maxDelay = 60,
    ) {
        BoundedNumber::assertAtLeast($retries, 0, 'back_channel_logout.retries', 'retries');
        BoundedNumber::assertAtLeast($delay, 1, 'back_channel_logout.retry_delay', 'seconds');
        BoundedNumber::assertAtLeast($multiplier, 1, 'back_channel_logout.retry_multiplier', 'times');
        BoundedNumber::assertAtLeast($maxDelay, 1, 'back_channel_logout.retry_max_delay', 'seconds');
    }

    public function isRetryable(Envelope $message, ?Throwable $throwable = null): bool
    {
        return RedeliveryStamp::getRetryCountFromEnvelope($message) < $this->retries;
    }

    /**
     * @return int milliseconds, which is what the worker waits in
     */
    public function getWaitingTime(Envelope $message, ?Throwable $throwable = null): int
    {
        return $this->waitBefore(RedeliveryStamp::getRetryCountFromEnvelope($message)) * 1000;
    }

    /**
     * The first send, then one per retry.
     */
    public function attempts(): int
    {
        return $this->retries + 1;
    }

    /**
     * The seconds spent waiting between the first send and the last, the whole schedule at once.
     */
    public function waiting(): int
    {
        $waiting = 0;
        for ($retry = 0; $retry < $this->retries; ++$retry) {
            $waiting += $this->waitBefore($retry);
        }

        return $waiting;
    }

    /**
     * Seconds. The ceiling is applied at each step rather than at the end, so that a long schedule counts
     * in seconds instead of overflowing.
     */
    private function waitBefore(int $retry): int
    {
        $wait = $this->delay;
        for ($step = 0; $step < $retry; ++$step) {
            $wait = min($this->maxDelay, $wait * $this->multiplier);
        }

        return $wait;
    }
}
