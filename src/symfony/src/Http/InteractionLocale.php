<?php

declare(strict_types=1);

namespace Heidi\Bundle\Http;

use function array_filter;
use function array_map;
use function array_slice;
use function array_unique;
use function array_values;
use function ctype_alpha;
use function ctype_digit;
use Heidi\Bundle\Plane\Plane;
use Heidi\Oidc\Domain\Interaction\Interaction;
use function implode;
use function in_array;
use function is_string;
use function preg_split;
use function str_starts_with;
use function strlen;
use function strtolower;
use function strtoupper;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Translation\LocaleSwitcher;
use function ucfirst;

/**
 * The language of the pages of the interaction plane (architecture §5.7). It is chosen once, when the
 * request reaches "/authorize": the "ui_locales" of the request (OIDC Core §3.1.2.1), most preferred
 * first, matched against the locales the deployment enables; then the "Accept-Language" of the browser
 * the same way; then the default locale of the deployment, which is the default of the one tenant of
 * spike 1. The choice is stored on the interaction and applied again on every page of it, so that a user
 * who begins in French finishes in French whatever their browser says on the next page; it never travels
 * in the URL, because the relying party does not know the language of the user and a login URL must not
 * change with it.
 *
 * A language tag is matched the way Symfony matches an Accept-Language: "fr-CA" is "fr_CA" when that
 * locale is enabled and "fr" otherwise, a script subtag is kept ("zh-Hant-TW" tries "zh_Hant_TW",
 * "zh_Hant", "zh_TW", "zh"), anything else in the tag is ignored. A tag no enabled locale matches is
 * skipped, never refused: §3.1.2.1 says the provider "SHOULD NOT" fail on it.
 *
 * Before the controller runs, the pages of the plane get the locale of the browser and of the deployment
 * (a page shown without an interaction, the error page of a refused request, the logout confirmation):
 * this listener sits above the LocaleListener of the kernel (16), which reads the "_locale" attribute it
 * sets, and above the listener (15) that hands the locale to the translator. A page of an interaction
 * then switches to the locale the interaction recorded.
 */
final readonly class InteractionLocale
{
    /**
     * Above the LocaleListener of the kernel (16), below the router (32) which names the route.
     */
    public const int PRIORITY = 17;

    /**
     * @param list<string> $enabledLocales the locales of "framework.enabled_locales"; the default locale alone when the application enables none
     */
    public function __construct(
        private LocaleSwitcher $switcher,
        private array $enabledLocales,
        private string $defaultLocale,
    ) {
    }

    /**
     * @param list<string> $uiLocales language tags, most preferred first (OIDC Core §3.1.2.1 "ui_locales", RP-Initiated Logout §2)
     */
    public function choose(Request $request, array $uiLocales = []): string
    {
        return $this->match($uiLocales) ?? $this->match(array_values($request->getLanguages())) ?? self::canonical($this->defaultLocale);
    }

    /**
     * Makes the locale the one of this request and of everything that translates during it: the request
     * itself, from which the response takes its Content-Language, and every locale-aware service through
     * the switcher of the translation component, which the kernel resets after the request.
     */
    public function apply(Request $request, string $locale): void
    {
        $request->setLocale($locale);
        $this->switcher->setLocale($locale);
    }

    /**
     * A page of an interaction speaks the language the interaction recorded on "/authorize"; an
     * interaction that recorded none (begun by an integration that chose not to) keeps the locale of the
     * request.
     */
    public function resume(Request $request, Interaction $interaction): void
    {
        if ($interaction->locale !== null) {
            $this->apply($request, $interaction->locale);
        }
    }

    #[AsEventListener(event: KernelEvents::REQUEST, priority: self::PRIORITY)]
    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $route = $request->attributes->get('_route');
        if (! $event->isMainRequest() || ! is_string($route) || ! str_starts_with($route, Plane::INTERACTION_ROUTE_PREFIX)) {
            return;
        }
        $request->attributes->set('_locale', $this->choose($request));
    }

    /**
     * @return list<string> the enabled locales, in canonical form, the default locale first
     */
    public function enabledLocales(): array
    {
        $enabled = array_map(self::canonical(...), [$this->defaultLocale, ...$this->enabledLocales]);

        return array_values(array_unique(array_filter($enabled, static fn (string $locale): bool => $locale !== '')));
    }

    /**
     * The first enabled locale one of the tags, in order, matches; a tag that matches nothing is skipped.
     *
     * @param list<string> $tags
     */
    private function match(array $tags): ?string
    {
        $enabled = $this->enabledLocales();
        foreach ($tags as $tag) {
            foreach (self::candidates($tag) as $candidate) {
                if (in_array($candidate, $enabled, true)) {
                    return $candidate;
                }
            }
        }

        return null;
    }

    /**
     * The canonical form of a tag: the language in lowercase, the script capitalised, the region in
     * uppercase, joined by underscores; "" for a tag that names no language.
     */
    private static function canonical(string $tag): string
    {
        return self::candidates($tag)[0] ?? '';
    }

    /**
     * The locales a tag may stand for, most specific first, RFC 5646 §2.2 read the way Request reads an
     * Accept-Language: language, then script (four letters) and region (two letters or three digits) when
     * the tag carries them; variants, extensions and private use are ignored.
     *
     * @return list<string>
     */
    private static function candidates(string $tag): array
    {
        $subtags = preg_split('/[-_]/', $tag);
        if ($subtags === false) {
            return [];
        }
        $language = strtolower($subtags[0] ?? '');
        if ($language === '' || ! ctype_alpha($language)) {
            return [];
        }
        $script = null;
        $region = null;
        foreach (array_slice($subtags, 1) as $subtag) {
            $length = strlen($subtag);
            if ($script === null && $region === null && $length === 4 && ctype_alpha($subtag)) {
                $script = ucfirst(strtolower($subtag));
            } elseif ($region === null && (($length === 2 && ctype_alpha($subtag)) || ($length === 3 && ctype_digit($subtag)))) {
                $region = strtoupper($subtag);
            }
        }

        $present = static fn (?string $subtag): bool => $subtag !== null;

        return array_values(array_unique([
            implode('_', array_filter([$language, $script, $region], $present)),
            implode('_', array_filter([$language, $script], $present)),
            implode('_', array_filter([$language, $region], $present)),
            $language,
        ]));
    }
}
