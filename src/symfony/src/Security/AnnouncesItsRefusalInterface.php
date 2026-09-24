<?php

declare(strict_types=1);

namespace Heidi\Bundle\Security;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * A login whose refusals the bundle announces (architecture §3.4, §3.5). What a refusal of this kind
 * means is the login's to read: what was typed, what the badge carries, and what the firewall wrapped
 * the cause in differ from one login to the next, and only the login knows its own.
 *
 * A login that announces its refusals itself, as the second step does through the core, implements
 * nothing here and the listener has nothing to add on its route.
 */
interface AnnouncesItsRefusalInterface extends ProvingLoginInterface
{
    /**
     * The route the firewall refuses this login on, which is what tells one login of the bundle from
     * another and from a firewall of the application.
     *
     * @return non-empty-string
     */
    public function route(): string;

    /**
     * @return LoginFailure|null null when nothing was attempted on an account, which is not a refused
     *                           login and is announced as nothing
     */
    public function refusal(AuthenticationException $exception, ?Passport $passport): ?LoginFailure;
}
