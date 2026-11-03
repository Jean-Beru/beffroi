<?php

declare(strict_types=1);

namespace App\Http;

use function array_values;
use App\Locale\LocalePreference;
use App\Locale\ServedLocales;
use App\Locale\UserLocale;
use App\Plane\Plane;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Port\AmbientTenantInterface;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use function str_starts_with;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Translation\LocaleSwitcher;

/**
 * The language of the pages of the interaction plane (architecture §5.7): what the record of whoever is
 * signed in says, then what the visitor asked for (BrowserPreferences), then "ui_locales" (OIDC Core §3.1.2.1),
 * then "Accept-Language", then the default locale, each read against the locales this deployment serves;
 * a tag nothing matches is skipped. Chosen once on "/authorize", recorded on the interaction, never in
 * the URL.
 *
 * **A person who is signed in reads these pages in the language of their record** (issue #485), and
 * changes it where that record is changed (§5.2). So the control that offers a language is for whoever is
 * not known yet, and a page that an account answered for says so, which is what the control reads to
 * offer nothing (Twig\LocaleExtension).
 */
final readonly class InteractionLocale
{
    /**
     * Above the LocaleListener of the kernel (16), below the router (32).
     */
    public const int PRIORITY = 17;

    /**
     * The attribute a page carries when the record of a person answered its language, which is what says
     * there is nothing to offer that person.
     */
    public const string OF_THE_ACCOUNT = '_beffroi_locale_of_the_account';

    public function __construct(
        private LocaleSwitcher $switcher,
        private ServedLocales $served,
        private BrowserPreferences $preferences,
        private BrowserSession $browser,
        private AmbientTenantInterface $tenants,
        private UserLocale $persons,
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
        $theirs = $this->ofTheAccount($request);
        if ($theirs !== null) {
            $request->attributes->set(self::OF_THE_ACCOUNT, true);

            return $theirs;
        }

        return (
            $this->preferences->read($request, LocalePreference::SLOT)
            ?? $this->served->match($uiLocales)
            ?? $this->served->match(array_values($request->getLanguages()))
            ?? $this->served->default
        );
    }

    /**
     * The language the record of whoever is signed in names, and null when nobody is or when the record
     * names none, or one this deployment does not serve. A unit of work with no tenant has nobody signed
     * in either, which is what a deployment before its first provisioning is, and that is not a question
     * of language (AmbientTenantInterface).
     */
    private function ofTheAccount(Request $request): ?string
    {
        try {
            $session = $this->browser->authenticationSession($request, $this->tenants->provide());
        } catch (RuntimeException) {
            return null;
        }

        return $session === null ? null : $this->persons->claimedBy($session->user);
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
