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
 *
 * An address of a federated domain, typed at the page of the address or hinted by the client, is kept apart, by the
 * same keys and under the same bound, for the sign-on the discovery sends the browser to, which takes it once and
 * carries it to a provider that reads one (S-68): never in a URL, so that no page of another site hands a sign-on an
 * address of its choosing.
 */
final readonly class LoginAddresses
{
    public const string SESSION_KEY = '_beffroi_login_addresses';

    public const string SENT_SESSION_KEY = '_beffroi_login_addresses_sent';

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
     * Back to the step of the address, for another one: what was typed for that login forgotten, the address kept for
     * its sign-on with it.
     */
    public function forget(SessionInterface $httpSession, ?Interaction $interaction): void
    {
        $passed = self::passedOnes($httpSession);
        unset($passed[self::key($interaction)]);
        $httpSession->set(self::SESSION_KEY, $passed);
        $sent = self::sentOnes($httpSession);
        unset($sent[self::key($interaction)]);
        $httpSession->set(self::SENT_SESSION_KEY, $sent);
    }

    /**
     * S-68: the address of a federated domain the discovery sends to the sign-on of its provider, kept for that sign-on,
     * as it was given.
     *
     * @param Interaction|null $interaction null for the login a page of the provider waits for
     */
    public function sendOn(SessionInterface $httpSession, ?Interaction $interaction, string $address): void
    {
        $sent = self::sentOnes($httpSession);
        $key = self::key($interaction);
        unset($sent[$key]);
        $sent[$key] = $address;
        $httpSession->set(self::SENT_SESSION_KEY, array_slice($sent, -self::MAX_KEPT, preserve_keys: true));
    }

    /**
     * S-68: the address kept for the sign-on of that login, forgotten as it is read, so that a sign-on the discovery did
     * not send the browser to, the request sent once more among them, carries none; null when none is kept.
     */
    public function takeSent(SessionInterface $httpSession, ?Interaction $interaction): ?string
    {
        $sent = self::sentOnes($httpSession);
        $key = self::key($interaction);
        $address = $sent[$key] ?? null;
        if ($address === null) {
            return null;
        }
        unset($sent[$key]);
        $httpSession->set(self::SENT_SESSION_KEY, $sent);

        return $address;
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

    /**
     * @return array<string, string>
     */
    private static function sentOnes(SessionInterface $httpSession): array
    {
        $stored = $httpSession->get(self::SENT_SESSION_KEY);
        if (! is_array($stored)) {
            return [];
        }
        $sent = [];
        foreach ($stored as $login => $address) {
            if (is_string($login) && is_string($address)) {
                $sent[$login] = $address;
            }
        }

        return $sent;
    }
}
