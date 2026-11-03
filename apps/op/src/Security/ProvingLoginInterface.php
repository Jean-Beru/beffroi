<?php

declare(strict_types=1);

namespace App\Security;

use Beffroi\Core\Domain\Session\AuthenticationMethod;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * A way of signing in that the firewall of the interaction pages offers, and what it proves as "amr"
 * values (RFC 8176 §2): what one passport proved, for the session the listener opens, and everything a
 * login of this kind may ever prove, for the discovery and the step-up (decision 0010). One class per
 * login, tagged "beffroi.login": what is tagged is what the provider announces, so an application whose
 * firewall offers a login of its own adds a class here, and one that offers fewer than the provider
 * declares removes the service of those it does not wire.
 */
interface ProvingLoginInterface
{
    /**
     * What this passport proved, or null when it did not come from this login.
     *
     * @return non-empty-list<AuthenticationMethod>|null
     */
    public function proofs(Passport $passport): ?array;

    /**
     * Every method a login of this kind may prove, whoever signs in with it and whatever they hold.
     *
     * @return non-empty-list<AuthenticationMethod>
     */
    public function everyProvableMethod(): array;
}
