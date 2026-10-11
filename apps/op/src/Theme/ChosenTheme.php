<?php

declare(strict_types=1);

namespace App\Theme;

use Beffroi\Bundle\Http\BrowserPreferences;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The theme of whoever is in front of the pages, read and written on the slot ThemePreference declares
 * (issue #447).
 *
 * Read on the server and not in a script, so that a page is rendered in the theme it was asked for and
 * never shows the other one first. It is a preference and not a credential: a forged choice changes a
 * colour, which is why it travels on the cookie of the preferences of a browser, beside the language, and
 * not on one of this application (architecture §5.7).
 */
final readonly class ChosenTheme
{
    public function __construct(
        private RequestStack $requests,
        private BrowserPreferences $preferences,
    ) {
    }

    public function current(): Theme
    {
        $request = $this->requests->getCurrentRequest();

        return Theme::ofChoice($request === null ? null : $this->preferences->read($request, ThemePreference::SLOT));
    }

    /**
     * The cookie that carries this choice and leaves the language of this browser as it was: the form of
     * the theme posts one thing, and the bundle writes the whole cookie from the request.
     */
    public function cookie(Request $request, Theme $theme): Cookie
    {
        return $this->preferences->cookie($request, ThemePreference::SLOT, $theme->value);
    }
}
