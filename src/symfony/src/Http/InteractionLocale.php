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
 * The language of the pages of the interaction plane (architecture §5.7): "ui_locales" (OIDC Core
 * §3.1.2.1), then "Accept-Language", then the default locale, matched against the enabled locales; a tag
 * nothing matches is skipped. Chosen once on "/authorize", recorded on the interaction, never in the URL.
 */
final readonly class InteractionLocale
{
    /**
     * Above the LocaleListener of the kernel (16), below the router (32).
     */
    public const int PRIORITY = 17;

    /**
     * @param list<string> $enabledLocales "framework.enabled_locales"
     */
    public function __construct(
        private LocaleSwitcher $switcher,
        private array $enabledLocales,
        private string $defaultLocale,
    ) {
    }

    /**
     * @param list<string> $uiLocales most preferred first
     */
    public function choose(Request $request, array $uiLocales = []): string
    {
        return $this->match($uiLocales) ?? $this->match(array_values($request->getLanguages())) ?? self::canonical($this->defaultLocale);
    }

    /**
     * The locale of the request and of everything that translates during it.
     */
    public function apply(Request $request, string $locale): void
    {
        $request->setLocale($locale);
        $this->switcher->setLocale($locale);
    }

    /**
     * An interaction that recorded no locale keeps the one of the request.
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
        $route = $request->attributes->getString('_route');
        if (! $event->isMainRequest() || ! str_starts_with($route, Plane::INTERACTION_ROUTE_PREFIX)) {
            return;
        }
        $request->attributes->set('_locale', $this->choose($request));
    }

    /**
     * @return list<string> canonical, the default locale first
     */
    public function enabledLocales(): array
    {
        $enabled = array_map(self::canonical(...), [$this->defaultLocale, ...$this->enabledLocales]);

        return array_values(array_unique(array_filter($enabled, static fn (string $locale): bool => $locale !== '')));
    }

    /**
     * The first enabled locale a tag matches, in order.
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
     * "fr_CA", "zh_Hant_TW"; "" for a tag that names no language.
     */
    private static function canonical(string $tag): string
    {
        return self::candidates($tag)[0] ?? '';
    }

    /**
     * RFC 5646 §2.2 read the way Request reads an Accept-Language: language, script and region, most
     * specific first; the rest is ignored.
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
