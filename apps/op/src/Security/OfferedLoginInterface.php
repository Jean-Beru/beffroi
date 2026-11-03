<?php

declare(strict_types=1);

namespace App\Security;

/**
 * A login a browser can start on the login page, naming the kind of credential it reads (architecture
 * §5.4): the password form and the passkey are two of them, the code of a second step is not, it continues
 * a login the page has already started.
 *
 * It exists so that the page offers what is wired and what the tenant admits, and nothing else (issue
 * #327): the kinds are read from the logins tagged "beffroi.login.offered" and filtered by the floor of
 * the tenant (OfferedLogins), so a tenant that signs its users in by passkey shows no password field and
 * no username, and a deployment that wires a login of its own has it offered by tagging its class.
 */
interface OfferedLoginInterface extends ProvingLoginInterface
{
    /**
     * The kind of credential this login reads, as the credential names itself (Credential::kind()): the
     * page shows a form per kind and names it in the one translation of that kind.
     */
    public function kind(): string;
}
