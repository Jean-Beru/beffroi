<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Bundle\Security\OfferedLoginInterface;
use Beffroi\Core\Domain\Tenant\Tenant;
use LogicException;
use function array_keys;
use function implode;
use function sprintf;

/**
 * The kinds of login the page of a tenant offers (issue #327): the logins the firewall wires, less those
 * whose proofs the floor of the tenant never reads. A tenant that signs its users in by passkey is shown
 * the passkey and nothing else, where the page used to hold its two forms whatever the tenant was; the
 * username goes with the password, a passkey being signed by a discoverable credential that names its own
 * user (WebAuthn Level 3 §6.3.2.1).
 *
 * It is the page's half of what ProvableMethodsInterface answers for the protocol: both read the wired
 * logins and the same floor, so the page cannot offer a way in the discovery does not announce.
 */
final readonly class OfferedLogins
{
    /**
     * @param iterable<OfferedLoginInterface> $logins the logins a browser can start, at least one
     */
    public function __construct(
        private iterable $logins,
    ) {
    }

    /**
     * @throws LogicException when the floor of the tenant admits none of the wired logins: nobody could
     *                        sign in, which is a deployment to fix and not a page to render empty
     *
     * @return non-empty-list<string> the kinds, in the order the logins are tagged
     */
    public function kinds(Tenant $tenant): array
    {
        $kinds = [];
        $closed = [];
        foreach ($this->logins as $login) {
            if ($tenant->loginFloor->admits($login->everyProvableMethod())) {
                $kinds[$login->kind()] = true;
            } else {
                $closed[$login->kind()] = true;
            }
        }
        if ($kinds === []) {
            throw new LogicException(sprintf(
                'The tenant "%s" requires "%s" of every login and this provider wires no login that proves it; it wires %s.',
                $tenant->slug,
                $tenant->loginFloor->name(),
                $closed === [] ? 'none at all' : implode(', ', array_keys($closed)),
            ));
        }

        return array_keys($kinds);
    }
}
