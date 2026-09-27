<?php

declare(strict_types=1);

namespace Heidi\Bundle\Ciba;

use Heidi\Bundle\Push\PushMessage;
use Heidi\Bundle\Push\WebPushSender;
use Heidi\Core\Application\Push\PushSubscriptionRevocation;
use Heidi\Core\Domain\Identity\PushSubscription;
use Heidi\Core\Domain\Identity\User;
use Heidi\Core\Port\PushSubscriptionRepositoryInterface;
use Heidi\Oidc\Domain\Ciba\PendingApproval;
use function implode;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use function sprintf;
use Symfony\Component\Messenger\Exception\RecoverableMessageHandlingException;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The one channel the bundle ships (architecture §5.6): the browsers of the user, reached through their
 * own push services (RFC 8030). It is the one way of reaching somebody whose premise this provider
 * already holds, a browser they signed in with, rather than an application store or an address book, and
 * it is wired by a deployment like any other channel.
 *
 * What is sent is what a PendingApproval carries and nothing more: the provider that is asking, the
 * client that asked, what that client wrote, and the page where a user finds what is waiting for them.
 * No identifier of the request and no link that answers one (BCP 10027 §5.2): the notification says that
 * something is waiting, and the user goes to the provider they already know.
 *
 * Every browser of the user is pushed to, and what comes back is a fact about that browser: a push
 * service that says the subscription is gone has taken it out, and the row is revoked here rather than
 * tried again forever. What is left is the attempt, and the lane is told to come back only when no
 * browser at all was reached: one browser that got it is a user who was told.
 */
final readonly class WebPushApprovalChannel implements PendingApprovalChannelInterface
{
    public const string TRANSLATION_DOMAIN = 'heidi';

    public function __construct(
        private PushSubscriptionRepositoryInterface $subscriptions,
        private PushSubscriptionRevocation $revocation,
        private WebPushSender $sender,
        private TranslatorInterface $translator,
        private ClockInterface $clock,
        private LoggerInterface $logger,
    ) {
    }

    public function tell(User $user, PendingApproval $approval): void
    {
        $subscriptions = $this->subscriptions->findActiveByUser($user);
        if ($subscriptions === []) {
            // a user this deployment cannot reach is not a failure of anything: they find the request on
            // the page where requests are answered, which is where this notification would send them
            return;
        }
        $message = $this->message($approval);
        $reached = false;
        $failures = [];
        foreach ($subscriptions as $subscription) {
            $delivery = $this->sender->send($subscription, $message);
            $reached = $reached || $delivery->delivered;
            if ($delivery->delivered) {
                $subscription->markPushed($this->clock->now());
                $this->subscriptions->save($subscription);

                continue;
            }
            if ($delivery->gone) {
                $this->revocation->revoke($subscription);
                $this->logger->info('A push subscription is gone and has been taken out.', self::trail($subscription, $delivery->detail));

                continue;
            }
            $failures[] = $delivery->detail;
            $this->logger->warning('A push notification was not taken.', self::trail($subscription, $delivery->detail));
        }
        if (! $reached && $failures !== []) {
            throw new RecoverableMessageHandlingException(sprintf(
                'No browser of this user was reached: %s.',
                implode('; ', $failures),
            ));
        }
    }

    /**
     * The words of the notification, in the language of the deployment: there is nobody in front of a
     * browser to read an "Accept-Language" from and no interaction to take a "ui_locales" from, this
     * being sent out of any request of the user (§5.7).
     */
    private function message(PendingApproval $approval): PushMessage
    {
        $binding = $approval->bindingMessage;

        return new PushMessage(
            $this->translator->trans(
                'push.approval.title',
                [
                    'provider' => $approval->tenant->name,
                ],
                self::TRANSLATION_DOMAIN,
            ),
            $binding === null
                ? $this->translator->trans(
                    'push.approval.body',
                    [
                        'client' => $approval->clientName,
                    ],
                    self::TRANSLATION_DOMAIN,
                )
                : $this->translator->trans(
                    'push.approval.body_with_message',
                    [
                        'client' => $approval->clientName,
                        'message' => $binding->value,
                    ],
                    self::TRANSLATION_DOMAIN,
                ),
            $approval->approvalUri,
            $approval->expiresAt,
        );
    }

    /**
     * What a log line says of a subscription: which one it was and what came back, never its endpoint,
     * which names a browser of somebody at their push service.
     *
     * @return array<string, string>
     */
    private static function trail(PushSubscription $subscription, string $detail): array
    {
        return [
            'subscription' => $subscription->id->toRfc4122(),
            'tenant' => $subscription->tenant->slug,
            'detail' => $detail,
        ];
    }
}
