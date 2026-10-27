<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Push;

use DateTimeImmutable;
use Beffroi\Core\Domain\Identity\PushSubscription;
use Beffroi\Core\Exception\ExceptionTrail;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Port\ApplicationServerKeyProviderInterface;
use function is_string;
use Psr\Clock\ClockInterface;
use function sprintf;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Throwable;
use WebPush\ExtensionManager;
use WebPush\Notification;
use WebPush\Payload\AES128GCM;
use WebPush\Payload\PayloadExtension;
use WebPush\Subscription;
use WebPush\TTLExtension;
use WebPush\UrgencyExtension;
use WebPush\VAPID\VAPIDExtension;
use WebPush\VAPID\WebTokenProvider;
use WebPush\WebPush;

/**
 * Leaves one message with the push service of one browser (RFC 8030, RFC 8291, RFC 8292). The payload is
 * encrypted to the two keys that browser gave, so the push service carries a length and nothing else, and
 * the request is signed by the application server key that browser subscribed under, which is the only
 * one the push service will take for it (RFC 8292 §4.2).
 *
 * The key is looked up by the "kid" the subscription carries and not by what is active now: a rotation
 * moves what a new browser subscribes under and never what an old one is bound to (architecture §3.3). A
 * subscription whose key has retired is worth nothing, and is answered so rather than pushed to.
 *
 * What becomes of the message after the push service has it, this provider never learns: RFC 8030 §5 is
 * a store and forward, and a 201 says it was taken, not that it was shown.
 */
final readonly class WebPushSender
{
    /**
     * RFC 8030 §5.3: what a user is being asked to confirm now is not a message that may wait for the
     * device to wake up on its own.
     */
    private const string URGENCY = 'high';

    /**
     * RFC 8291 §4: the one content encoding this provider encrypts with, and the one a browser is told
     * to expect. "aesgcm" is the draft that came before it and is not offered.
     */
    private const string CONTENT_ENCODING = 'aes128gcm';

    /**
     * The length every notification of this provider is padded to before it is encrypted (RFC 8291 §4), so
     * that what a push service carries is the same size whatever it says: the words are short and the shape
     * is always the same three members, so their length would otherwise tell a push service how long a
     * client's binding message is.
     *
     * A constant and not the library's recommendation, which pads to 3052 and leaves under a kilobyte of the
     * 4096 octets RFC 8291 §4 allows: what a client wrote is text this provider did not choose, and a
     * notification that grows into the ceiling is one the sender refuses outright rather than delivers
     * shorter.
     */
    private const int PADDED_TO = 1024;

    /**
     * @param string $subject the "sub" of the signed token, a "mailto:" or "https:" URI a push service can
     *                        reach this deployment at when something is wrong with what it sends
     *                        (RFC 8292 §2.1); not empty, which the tree refuses written and which a
     *                        variable of the environment can only be refused for here
     * @param float $timeout seconds given to a push service before a worker is given back
     *
     * @throws InvalidConfigurationException when the subject is empty
     */
    public function __construct(
        private ApplicationServerKeyProviderInterface $keys,
        private HttpClientInterface $http,
        private ClockInterface $clock,
        public string $subject,
        public float $timeout,
    ) {
        if ($subject === '') {
            throw new InvalidConfigurationException('The "beffroi" configuration key "web_push.subject" names the "mailto:" or "https:" URI a push service can reach the operator at (RFC 8292 section 2.1), and it is empty.');
        }
    }

    public function send(PushSubscription $subscription, PushMessage $message): PushDelivery
    {
        try {
            $unsealed = $this->keys->applicationServerKey($subscription->tenant, $subscription->applicationServerKid);
        } catch (KeyNotFoundException $exception) {
            return PushDelivery::gone($exception->getMessage());
        }
        $privateKey = $unsealed->privateJwk['d'] ?? null;
        if (! is_string($privateKey)) {
            return PushDelivery::unreachable('the application server key of the tenant carries no private half');
        }
        try {
            $report = $this->webPush(ApplicationServerKey::of($unsealed->key)->publicKey, $privateKey)->send(
                self::notification($message, $this->clock->now()),
                self::subscription($subscription),
            );
        } catch (Throwable $exception) {
            return PushDelivery::unreachable(sprintf('the push service cannot be reached: %s', ExceptionTrail::of($exception)));
        }
        if ($report->isSuccess()) {
            return PushDelivery::delivered($report->getStatusCode());
        }

        return $report->isSubscriptionExpired()
            ? PushDelivery::gone(sprintf('the push service answered %d: the subscription is gone', $report->getStatusCode()))
            : PushDelivery::unreachable(sprintf('the push service answered %d', $report->getStatusCode()));
    }

    private function webPush(string $publicKey, string $privateKey): WebPush
    {
        $extensions = ExtensionManager::create()
            ->add(TTLExtension::create())
            ->add(UrgencyExtension::create())
            ->add(PayloadExtension::create()->addContentEncoding(AES128GCM::create($this->clock)->customPadding(self::PADDED_TO)))
            ->add(VAPIDExtension::create($this->subject, new WebTokenProvider($publicKey, $privateKey), $this->clock));

        return WebPush::create($this->http->withOptions([
            'timeout' => $this->timeout,
            'max_duration' => $this->timeout,
            'max_redirects' => 0,
        ]), $extensions);
    }

    private static function notification(PushMessage $message, DateTimeImmutable $now): Notification
    {
        return Notification::create()->withTTL($message->timeToLive($now))->withUrgency(self::URGENCY)->withPayload($message->payload());
    }

    private static function subscription(PushSubscription $subscription): Subscription
    {
        return Subscription::create($subscription->endpoint)
            ->withContentEncodings([self::CONTENT_ENCODING])
            ->setKey('p256dh', $subscription->publicKey)
            ->setKey('auth', $subscription->authSecret);
    }
}
