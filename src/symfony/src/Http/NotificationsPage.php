<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Bundle\Push\ApplicationServerKey;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Port\ApplicationServerAlgorithmsInterface;
use Beffroi\Core\Port\ApplicationServerKeyProviderInterface;
use Beffroi\Core\Port\PushSubscriptionRepositoryInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page where a user says which of their browsers this provider may reach (Push API §4, architecture
 * §5.2): what is subscribed now, a button that subscribes this one, and a button that takes one out.
 *
 * The application server key of the tenant is handed to the page because the browser needs it to
 * subscribe at all (RFC 8292 §3.2), and it is the public half of a key pair: there is nothing of a user
 * in it and nothing a third party could not have been given. A deployment that wires no such algorithm,
 * or a tenant whose key has not been drawn yet, has no key to hand out, and the page says that this
 * provider reaches nobody this way rather than offering a button that cannot work.
 */
final readonly class NotificationsPage
{
    public function __construct(
        private PushSubscriptionRepositoryInterface $subscriptions,
        private ApplicationServerAlgorithmsInterface $algorithms,
        private ApplicationServerKeyProviderInterface $keys,
        private InteractionPages $pages,
    ) {
    }

    /**
     * @param string|null $error a code the template translates
     */
    public function render(User $user, ?string $error = null, int $status = Response::HTTP_OK): Response
    {
        return $this->pages->render(
            'account/notifications.html.twig',
            [
                'user' => $user,
                'subscriptions' => $this->subscriptions->findActiveByUser($user),
                'application_server_key' => $this->applicationServerKey($user)?->publicKey,
                'error' => $error,
            ],
            $status,
        );
    }

    /**
     * The key a browser of this user would subscribe under, null when this deployment hands none out.
     */
    public function applicationServerKey(User $user): ?ApplicationServerKey
    {
        $algorithm = $this->algorithms->all()[0] ?? null;
        if ($algorithm === null) {
            return null;
        }
        try {
            return ApplicationServerKey::of($this->keys->activeApplicationServerKey($user->tenant, $algorithm));
        } catch (KeyNotFoundException) {
            return null;
        }
    }
}
