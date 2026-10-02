<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Security;

use DateTimeImmutable;
use Beffroi\Core\Domain\Session\RequestContext;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * A login that dates the credential it proved, and announces what its kind announces of a use. What a
 * login writes down about itself is the login's, never a branch in the listener that opens the session:
 * a kind added to the firewall says here what it records, or says nothing by not implementing this.
 */
interface DatesItsCredentialInterface extends ProvingLoginInterface
{
    /**
     * @return bool true when the passport came from this login and its credential was dated, false when
     *              the passport is another login's
     */
    public function recordUse(Passport $passport, SecurityUser $user, DateTimeImmutable $now, RequestContext $context): bool;
}
