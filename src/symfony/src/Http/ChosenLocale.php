<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use Beffroi\Bundle\Locale\ServedLocales;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use function time;

/**
 * The language a visitor asked for, kept for their browser (issue #448, architecture §5.7).
 *
 * It is read on one cookie and never from the URL, which is the rule the language of the pages already
 * follows: a path that carries a locale is a second address for every page, and an authorization request
 * is answered at the address the client registered.
 *
 * What it holds is read back against the languages this deployment serves, so that a cookie somebody
 * wrote by hand names a language that has a catalogue or names nothing at all.
 */
final readonly class ChosenLocale
{
    public const string COOKIE = 'beffroi_locale';

    /**
     * A year: a visitor who said once is not asked again, and a browser that never comes back drops it.
     */
    public const int LIFETIME = 31_536_000;

    public function __construct(
        private ServedLocales $served,
    ) {
    }

    /**
     * The language this browser asked for, null when it asked for none or for one nobody serves here.
     */
    public function current(Request $request): ?string
    {
        $chosen = $request->cookies->getString(self::COOKIE);

        return $chosen === '' ? null : $this->served->match([$chosen]);
    }

    /**
     * No script reads it (HttpOnly), it does not leave the requests of this browser (SameSite=Lax), and
     * the issuer is served over TLS (Secure). It is a preference and not a credential.
     */
    public function cookie(string $locale): Cookie
    {
        return Cookie::create(
            self::COOKIE,
            $locale,
            time() + self::LIFETIME,
            '/',
            null,
            true,
            true,
            false,
            Cookie::SAMESITE_LAX,
        );
    }
}
