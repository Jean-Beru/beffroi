<?php

declare(strict_types=1);

namespace App\Message;

use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use Symfony\Component\Uid\Uuid;

/**
 * One logout token to carry to one relying party (Back-Channel Logout 1.0 §2.5, architecture §5.6). One
 * message per client rather than one per session: a client that cannot be reached is retried alone, and
 * the ones that answered are not told twice. What it carries is what the send and the giving up need,
 * the token included, because minting it again would ask the KMS for another signature. A Notification
 * and not a Command: it waits on a third party, and waits longer, on a transport of its own.
 *
 * It carries the person whose session ended, because what the giving up writes is an act of the journal of
 * that person (issue #588) and the message is the last thing that still knows who they are: the session is
 * closed, and nothing downstream of here reads one.
 */
final readonly class SendLogoutToken implements Notification
{
    public function __construct(
        public Tenant $tenant,
        public string $clientId,
        public string $logoutUri,
        public string $logoutToken,
        public Uuid $sessionId,
        public Subject $subject,
        public RequestContext $context,
    ) {
    }
}
