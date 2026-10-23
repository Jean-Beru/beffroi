<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function array_key_exists;
use function array_slice;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use function is_array;
use function is_string;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * The logins of a browser whose page passed the step of the address (beffroi/saml S-61): when the tenant federates a
 * domain, the login page asks for the address first, and shows the usual page once an address of no federated domain,
 * or a username, was typed for that login. Kept in the HTTP session of that browser and never in a URL, by interaction,
 * and under a key of its own for the login a page of the provider waits for (LoginTarget), which no identifier of an
 * interaction can be; at most eight, the oldest forgotten first, as the requests that wait for a login are kept
 * (WaitingSignOns); what was typed goes where the field of the username of the usual page reads it
 * (AuthenticationUtils::getLastUsername()).
 */
final readonly class LoginAddresses
{
    public const string SESSION_KEY = '_beffroi_login_addresses';

    public const int MAX_KEPT = 8;

    /**
     * The login a page of the provider waits for, which no identifier of an interaction is: those are base64url.
     */
    private const string WAITING_PAGE = ':page';

    /**
     * @param Interaction|null $interaction null for the login a page of the provider waits for
     */
    public function pass(SessionInterface $httpSession, ?Interaction $interaction, string $identifier): void
    {
        $passed = self::passedOnes($httpSession);
        $key = self::key($interaction);
        unset($passed[$key]);
        $passed[$key] = true;
        $httpSession->set(self::SESSION_KEY, array_slice($passed, -self::MAX_KEPT, preserve_keys: true));
        $httpSession->set(SecurityRequestAttributes::LAST_USERNAME, $identifier);
    }

    public function passed(SessionInterface $httpSession, ?Interaction $interaction): bool
    {
        return array_key_exists(self::key($interaction), self::passedOnes($httpSession));
    }

    /**
     * Back to the step of the address, for another one.
     */
    public function forget(SessionInterface $httpSession, ?Interaction $interaction): void
    {
        $passed = self::passedOnes($httpSession);
        unset($passed[self::key($interaction)]);
        $httpSession->set(self::SESSION_KEY, $passed);
    }

    private static function key(?Interaction $interaction): string
    {
        return $interaction->id ?? self::WAITING_PAGE;
    }

    /**
     * @return array<string, true>
     */
    private static function passedOnes(SessionInterface $httpSession): array
    {
        $stored = $httpSession->get(self::SESSION_KEY);
        if (! is_array($stored)) {
            return [];
        }
        $passed = [];
        foreach ($stored as $interaction => $true) {
            if (is_string($interaction) && $true === true) {
                $passed[$interaction] = true;
            }
        }

        return $passed;
    }
}
