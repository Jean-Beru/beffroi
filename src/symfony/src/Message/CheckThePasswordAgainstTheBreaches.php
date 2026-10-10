<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Message;

use Symfony\Component\Uid\Uuid;

/**
 * A password just signed somebody in, and a list of compromised passwords is to be asked about it (issue
 * #552). A Command: nothing of the login waits for it, which is the point of it being one. A password that
 * was clean the day it was written turns up in a corpus published a month later, and the login is the only
 * moment this provider holds the password at all.
 *
 * It names the credential by identifier and carries the SHA-1 of what was typed, because that is what
 * survives the queue it is written to: a credential is an entity of a tenant and does not leave the
 * process whole, and the digest is what the list is searched by (PasswordDigest). The tenant is not
 * carried either, being the one of the process, as the other commands of this provider say.
 *
 * **The body is sealed on its way out** (decision 0020): the serializer of every transport writes a JWE to
 * the message key of the tenant, so neither the broker nor the failure table holds the digest readable. It
 * is a digest and not a password, and it is still the one shape of a password that leaves a request.
 */
final readonly class CheckThePasswordAgainstTheBreaches implements Command
{
    public function __construct(
        public Uuid $credential,
        public string $digest,
    ) {
    }
}
