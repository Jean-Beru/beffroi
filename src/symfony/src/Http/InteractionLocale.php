<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Http;

use function array_values;
use Beffroi\Bundle\Locale\ServedLocales;
use Beffroi\Bundle\Plane\Plane;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use function str_starts_with;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Translation\LocaleSwitcher;

/**
 * The language of the pages of the interaction plane (architecture §5.7): what the visitor asked for
 * (ChosenLocale), then "ui_locales" (OIDC Core §3.1.2.1), then "Accept-Language", then the default
 * locale, each read against the locales this deployment serves; a tag nothing matches is skipped. Chosen
 * once on "/authorize", recorded on the interaction, never in the URL.
 */
final readonly class InteractionLocale
{
    /**
     * Above the LocaleListener of the kernel (16), below the router (32).
     */
    public const int PRIORITY = 17;

    public function __construct(
        private LocaleSwitcher $switcher,
        private ServedLocales $served,
        private ChosenLocale $chosen,
    ) {
    }

    /**
     * What a visitor asked for comes first, and that is the one thing decided here: "ui_locales" is what
     * a client guesses of the preference of whoever it sends over, which OIDC Core §3.1.2.1 calls a hint,
     * and a visitor who asks is that person saying it. Then the hint, then the languages the browser
     * sends, then the default; each read against what this deployment serves, and a tag nothing matches
     * is skipped.
     *
     * @param list<string> $uiLocales most preferred first
     */
    public function choose(Request $request, array $uiLocales = []): string
    {
        return (
            $this->chosen->current($request)
            ?? $this->served->match($uiLocales)
            ?? $this->served->match(array_values($request->getLanguages()))
            ?? $this->served->default
        );
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
}
