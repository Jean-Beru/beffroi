<?php

declare(strict_types=1);

namespace App\Doctor;

use function array_keys;
use function array_map;
use App\Message\SendLogoutToken;
use App\Messenger\NotificationRetryPolicy;
use Beffroi\Core\Exception\ExceptionTrail;
use DateInterval;
use DateTimeImmutable;
use function implode;
use function intdiv;
use function iterator_to_array;
use Beffroi\Oidc\Port\LogoutTokenDeliveryInterface;
use Psr\Container\ContainerInterface;
use ReflectionClass;
use function sprintf;
use Symfony\Component\Messenger\Envelope;
use Symfony\Component\Messenger\Retry\RetryStrategyInterface;
use Symfony\Component\Messenger\Stamp\RedeliveryStamp;
use Symfony\Component\Messenger\Transport\Sender\SenderInterface;
use Symfony\Component\Messenger\Transport\Sender\SendersLocatorInterface;
use Throwable;

/**
 * Whether a logout token is still being retried while it can be verified (issue #196).
 *
 * **What it guards.** A session that ends is announced to each client that opened it, by a signed logout
 * token posted to that client (Back-Channel Logout 1.0 §2.5). It is an HTTP call to somebody else's
 * server, so it is queued and retried, and how long it is retried is one value, `NotificationRetryPolicy`.
 * Two things are computed from that value: the `exp` of the token (`LogoutTokenIssuer`) and how long the
 * key that signed it is held in the JWK Set before it retires (`LogoutTokenJwsKind`, §3.3, §4.9). So the
 * provider stops trying exactly when what it sends stops being verifiable, which is what issue #155
 * settled.
 *
 * **What breaks it is one line of a deployment.** The transports are an application's, its broker and its
 * credentials with them, and the provider only prepends a default (`MessengerContract`). An application that
 * routes the notifications to a lane of its own, retried for longer, keeps a provider that works and two
 * numbers that no longer agree: a client reached on a late retry refuses a token whose `exp` has passed,
 * or whose signing key the JWK Set no longer publishes, the user stays signed in there, and nothing says
 * so. It shows after a key rotation or after a client restarts, never in a browser, and no test of a
 * deployment covers it, every lane being synchronous in a test environment. The provider cannot refuse an
 * application's transport and should not, so this is said rather than enforced.
 *
 * **It asks the container, never a file.** `messenger.senders_locator` names the transports a
 * `SendLogoutToken` envelope is sent to, and `messenger.retry_strategy_locator` gives the strategy of each
 * one, so what is read is the container a deployment boots and not the YAML it was written from.
 *
 * **It is the object and not the class that must match.** The two numbers are computed from the policy the
 * container holds, so the lane is right when it is retried by that very object: a second instance of the
 * same class is a second schedule, free to change without the other two following it.
 *
 * **It asks a strategy what it does rather than read its fields**, a strategy of a deployment having
 * whichever fields it likes: how many times it says a message may come back, and how long it says to wait
 * before each one. It asks without an exception, which is the question "what does this lane do when a send
 * fails", so a strategy that answers by the kind of failure answers here for the ordinary one.
 */
final readonly class NotificationsLanePatience implements CheckInterface
{
    public const string ABOUT = 'Back-channel logout: how long a logout token is retried';

    /**
     * How far the walk of a strategy goes before it calls it unbounded. Far past the retries of any
     * schedule the lifetime of a token could cover, and a bound all the same, because a strategy that
     * always says yes is a walk this must return from.
     */
    private const int RETRIES_WALKED = 1000;

    /**
     * @param ContainerInterface $strategies messenger.retry_strategy_locator, keyed by transport name
     * @param LogoutTokenDeliveryInterface $verifiable how long a logout token stays verifiable, which is
     *                                                 how long its signing key is held in the JWK Set and
     *                                                 how far ahead its "exp" is set
     */
    public function __construct(
        private SendersLocatorInterface $senders,
        private ContainerInterface $strategies,
        private NotificationRetryPolicy $policy,
        private LogoutTokenDeliveryInterface $verifiable,
    ) {
    }

    public function finding(): Finding
    {
        $verifiable = self::duration(self::secondsOf($this->verifiable->deliveryBudget()));

        try {
            $lanes = $this->lanesOfALogoutToken();
        } catch (Throwable $exception) {
            return Finding::red(self::ABOUT, [
                sprintf('What carries a logout token cannot be read from the container: %s', ExceptionTrail::of($exception)),
                self::whatItCosts($verifiable),
            ]);
        }

        if ($lanes === []) {
            return Finding::red(self::ABOUT, [
                sprintf(
                    'Nothing carries a logout token: "%s" is routed to no transport, so a client is told inside the request that asked for the logout, and a client that does not answer at that moment is never told at all.',
                    SendLogoutToken::class,
                ),
                self::whatItCosts($verifiable),
                self::WHAT_TO_DO,
            ]);
        }

        $found = [];
        foreach ($lanes as $lane) {
            $strategy = $this->strategyOf($lane);
            if ($strategy === $this->policy) {
                continue;
            }
            $found[] = $strategy === null
                ? sprintf(
                    'This deployment sends a logout token to the transport "%s" and nothing retries it there, so one failed send is a client never told, and the %s a token stays verifiable are waited by nobody.',
                    $lane,
                    $verifiable,
                )
                : sprintf(
                    'This deployment retries a logout token on the transport "%s" for %s. One stops being verifiable after %s, which is how far ahead its "exp" is set and how long the key that signed it stays in the JWK Set, both read from the schedule this provider publishes (%s); that transport is retried by %s instead.',
                    $lane,
                    self::retried(self::waitingOf($strategy)),
                    $verifiable,
                    NotificationRetryPolicy::class,
                    $strategy::class,
                );
        }

        if ($found !== []) {
            $found[] = self::whatItCosts($verifiable);
            $found[] = self::WHAT_TO_DO;

            return Finding::red(self::ABOUT, $found);
        }

        return Finding::green(self::ABOUT, sprintf(
            'A logout token is retried on %s for %s and stops being verifiable after %s, both read from the schedule this provider publishes (%s): a client that is restarting is reached, and nothing arrives after the "exp" of the token has passed or after the key that signed it has left the JWK Set.',
            implode(', ', array_map(static fn (string $lane): string => sprintf('"%s"', $lane), $lanes)),
            self::duration($this->policy->waiting()),
            $verifiable,
            NotificationRetryPolicy::class,
        ));
    }

    /**
     * What a reader loses by it, in what they would see: the one consequence, where it shows, and why
     * nothing else shows it.
     */
    private static function whatItCosts(string $verifiable): string
    {
        return sprintf(
            'What it costs: a user who signs out stays signed in on a client that was being retried, that client refusing a token whose "exp" has passed or whose signing key its JWK Set no longer publishes after %s. It shows after a key rotation or after a client restarts, it is never visible in a browser, and no test of a deployment covers it, every lane being synchronous in a test environment.',
            $verifiable,
        );
    }

    public const string WHAT_TO_DO = 'What to do: route the notifications back to the lane this provider declares ("async_notifications"), or give the transport this deployment chose the same schedule, "retry_strategy: { service: App\Messenger\NotificationRetryPolicy }". Writing the four numbers of a retry strategy on the lane the provider declares does nothing: the service it prepends survives the merge of a configuration that names no service, and the component prefers a service to its own numbers.';

    /**
     * The transports a logout token is sent to, as the container routes it.
     *
     * @return list<string>
     */
    private function lanesOfALogoutToken(): array
    {
        /** @var array<string, SenderInterface> $senders */
        $senders = iterator_to_array($this->senders->getSenders(new Envelope(self::aLogoutToken())));

        return array_keys($senders);
    }

    /**
     * What retries a transport, or null when nothing does.
     */
    private function strategyOf(string $lane): ?RetryStrategyInterface
    {
        if (! $this->strategies->has($lane)) {
            return null;
        }
        $strategy = $this->strategies->get($lane);

        return $strategy instanceof RetryStrategyInterface ? $strategy : null;
    }

    /**
     * The seconds a strategy spends waiting between the first send and the last, asked of the strategy
     * itself; null when it never gives up.
     */
    private static function waitingOf(RetryStrategyInterface $strategy): ?int
    {
        $message = self::aLogoutToken();
        $milliseconds = 0;
        for ($retry = 0; $retry < self::RETRIES_WALKED; ++$retry) {
            $envelope = new Envelope($message, [new RedeliveryStamp($retry)]);
            if (! $strategy->isRetryable($envelope)) {
                return intdiv($milliseconds, 1000);
            }
            $milliseconds += $strategy->getWaitingTime($envelope);
        }

        return null;
    }

    private static function retried(?int $seconds): string
    {
        return $seconds === null ? 'as long as it takes' : self::duration($seconds);
    }

    /**
     * Seconds as a reader counts them: a figure of six hundred is a figure nobody compares with anything.
     */
    private static function duration(int $seconds): string
    {
        if ($seconds < 60) {
            return sprintf('%d second%s', $seconds, $seconds === 1 ? '' : 's');
        }
        $minutes = sprintf('%d minute%s', intdiv($seconds, 60), intdiv($seconds, 60) === 1 ? '' : 's');
        $rest = $seconds % 60;

        return $rest === 0 ? $minutes : sprintf('%s %d second%s', $minutes, $rest, $rest === 1 ? '' : 's');
    }

    /**
     * An interval in seconds, counted from a date rather than read off the fields, an interval of a
     * deployment carrying its own.
     */
    private static function secondsOf(DateInterval $interval): int
    {
        $epoch = new DateTimeImmutable('@0');

        return $epoch->add($interval)->getTimestamp();
    }

    /**
     * The message the question is asked about, and not one this builds: a transport is chosen by the class
     * of the message, so the class is what the locators are asked about and no logout token is minted to
     * ask them. A check reads and writes nothing, and minting one would ask the KMS for a signature.
     */
    private static function aLogoutToken(): SendLogoutToken
    {
        return new ReflectionClass(SendLogoutToken::class)->newInstanceWithoutConstructor();
    }
}
