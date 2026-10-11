<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function array_key_exists;
use function array_keys;
use function explode;
use function ksort;
use function implode;
use LogicException;
use function sprintf;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use function time;

/**
 * What a browser asked the pages to look and read like, on one cookie with a slot per preference
 * (architecture §5.7): the language a visitor chose, the theme they read the pages in, and whatever a
 * preference added beside them declares. One cookie and not one per preference, because they are the same
 * thing as many times: same attributes, same year, each a preference and not a credential.
 *
 * **They are not in the HTTP session, and that is a decision and not an omission.** The session is lazy and
 * the protocol plane opens none (PlaneRequestListener), so a language would open a session for every visitor
 * who has not signed in; BrowserSession::unbind() invalidates the whole session, so a logout or an expiry
 * would drop a choice made for a year; and the theme is read when the first page is rendered, before there
 * is anything to open.
 *
 * What the cookie holds is read back through the preference that declared the slot, so a slot nobody
 * declared and a value nobody serves are both read as nothing: a cookie somebody wrote by hand names what
 * this deployment has or names nothing at all.
 */
final readonly class BrowserPreferences
{
    /**
     * The "__Host-" prefix of the name reverses who checks the three attributes the cookie below sets: a
     * browser refuses it outright unless it is Secure, unless its path is "/" and unless it names no
     * Domain, so a subdomain of the issuer cannot write a preference in its place either.
     */
    public const string COOKIE = '__Host-beffroi_preferences';

    /**
     * A year: a visitor who said once is not asked again, and a browser that never comes back drops it.
     */
    public const int LIFETIME = 31_536_000;

    /**
     * @var array<string, BrowserPreferenceInterface>
     */
    private array $declared;

    /**
     * @param iterable<BrowserPreferenceInterface> $preferences
     *
     * @throws LogicException when two preferences name one slot
     */
    public function __construct(iterable $preferences)
    {
        $declared = [];
        foreach ($preferences as $preference) {
            $slot = $preference->slot();
            if (array_key_exists($slot, $declared)) {
                throw new LogicException(sprintf('Two preferences of a browser name the slot "%s".', $slot));
            }
            $declared[$slot] = $preference;
        }
        $this->declared = $declared;
    }

    /**
     * What this browser asked for in one slot, and null when it asked for nothing, for something nobody
     * serves, or in a slot nothing declares.
     */
    public function read(Request $request, string $slot): ?string
    {
        return $this->held($request)[$slot] ?? null;
    }

    /**
     * The cookie that carries this choice and leaves every other slot as it was: the language form and the
     * theme form each post one thing, and a response of either rewrites the whole cookie, so what it does
     * not name is read from the request and written back.
     *
     * @throws LogicException when no preference declares the slot, or when the one that does does not serve
     *                        the value: both are a fault of the wiring or of the caller and never of a
     *                        request, what a request asks for being read before it gets here
     */
    public function cookie(Request $request, string $slot, string $value): Cookie
    {
        $preference = $this->declared[$slot] ?? throw new LogicException(sprintf(
            'No preference of a browser declares the slot "%s"; the wired ones are %s.',
            $slot,
            $this->declared === [] ? 'none' : '"' . implode('", "', array_keys($this->declared)) . '"',
        ));
        $served = $preference->read($value) ?? throw new LogicException(sprintf(
            'The preference of the slot "%s" does not serve the value "%s".',
            $slot,
            $value,
        ));

        $slots = [$slot => $served] + $this->held($request);
        // by name and not in the order the slots were wired or written: the value of the cookie is then the
        // same whatever wired what, so a preference added or moved in the wiring does not rewrite what every
        // browser already holds
        ksort($slots);
        $pairs = [];
        foreach ($slots as $declared => $value) {
            $pairs[] = $declared . '=' . $value;
        }

        /**
         * No script reads it (HttpOnly), it does not leave the requests of this browser (SameSite=Lax), and
         * the issuer is served over TLS, so it is never sent in clear (Secure). Those three, the path and
         * the absence of a Domain are what the name requires of it.
         */
        return Cookie::create(
            self::COOKIE,
            implode('&', $pairs),
            time() + self::LIFETIME,
            '/',
            null,
            true,
            true,
            false,
            Cookie::SAMESITE_LAX,
        );
    }

    /**
     * The slots this request carries that a preference declares and serves, by name.
     *
     * @return array<string, string>
     */
    private function held(Request $request): array
    {
        $held = [];
        foreach (explode('&', $request->cookies->getString(self::COOKIE)) as $pair) {
            [$slot, $value] = explode('=', $pair, 2) + [1 => ''];
            $served = ($this->declared[$slot] ?? null)?->read($value);
            if ($served !== null) {
                $held[$slot] = $served;
            }
        }

        return $held;
    }
}
