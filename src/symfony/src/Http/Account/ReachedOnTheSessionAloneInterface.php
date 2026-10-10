<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http\Account;

/**
 * A page of the account the session of the browser is enough to reach (architecture §5.2): it shows what
 * the account holds, or it changes something that is not a way in, and asking for a proof given a short
 * while ago would be asking a person to sign in again to read their own record.
 *
 * **Ending a session is the case that says it loudest.** Revoking a session is what a person does because
 * they fear that session, and asking them to prove themselves first is asking them to type a password on
 * the browser they are worried about. The pages of the sessions are here for that reason, and not because
 * nobody got to them.
 *
 * It carries nothing and is the other half of AsksForARecentProofInterface: what it says is that the
 * question was put to this page and answered no, which is what keeps the pages that ask from being a list
 * somebody has to remember to add to.
 */
interface ReachedOnTheSessionAloneInterface
{
}
