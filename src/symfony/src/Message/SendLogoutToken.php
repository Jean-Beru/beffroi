<?php

declare(strict_types=1);

namespace Heidi\Bundle\Message;

use Heidi\Core\Domain\Session\RequestContext;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Event\LogoutTokenIssued;
use Symfony\Component\Uid\Uuid;

/**
 * One logout token to carry to one relying party (Back-Channel Logout 1.0 §2.5, architecture §5.6). One
 * message per client rather than one per session: a client that cannot be reached is retried alone, and
 * the ones that answered are not told twice. What it carries is what the send and the giving up need,
 * the token included, because minting it again would ask the KMS for another signature. A Notification
 * and not a Command: it waits on a third party, and waits longer, on a transport of its own.
 */
final readonly class SendLogoutToken implements Notification
{
    public function __construct(
        public Tenant $tenant,
        public string $clientId,
        public string $logoutUri,
        public string $logoutToken,
        public Uuid $sessionId,
        public RequestContext $context,
    ) {
    }

    public static function of(LogoutTokenIssued $issued): self
    {
        return new self(
            $issued->tenant,
            $issued->clientId,
            $issued->logoutUri->value,
            $issued->token,
            $issued->sessionId,
            $issued->context,
        );
    }
}
