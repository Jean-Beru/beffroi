<?php

declare(strict_types=1);

namespace App\Message;

use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use SensitiveParameter;

/**
 * One word to carry to one client that registered to be told when the backchannel request it made has
 * been answered (CIBA Core §10.2, architecture §5.6). One message per request rather than one per client:
 * a request that could not be carried is tried again alone, and a client is never told twice about the
 * same one. A Notification and not a Command: it waits on a third party, and waits longer, on a transport
 * of its own.
 *
 * It carries the identifier of the request and the token of that client, because what the provider keeps
 * of both is sealed under the KMS of the tenant and opening them again is a round trip the retries must
 * not each pay for. It carries no token of the user and none of the answer: the client comes to the token
 * endpoint for that.
 */
final readonly class SendClientNotification implements Notification
{
    public function __construct(
        public Tenant $tenant,
        public string $clientId,
        public string $notificationEndpoint,
        #[SensitiveParameter]
        public string $notificationToken,
        #[SensitiveParameter]
        public string $authRequestId,
        public RequestContext $context,
    ) {
    }
}
