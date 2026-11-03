<?php

declare(strict_types=1);

namespace App\Controller;

use App\Doctrine\TenantProvider;
use App\Http\AuthorizationResponder;
use App\Http\BrowserSession;
use App\Http\BrowserPreferences;
use App\Http\FormToken;
use App\Http\RequestParameters;
use App\Message\RememberTheChosenLanguage;
use App\Locale\LocalePreference;
use App\Locale\ServedLocales;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use function is_string;
use function preg_match;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Messenger\MessageBusInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\AsController;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The language a visitor asks the pages to be read in (issue #448, architecture §5.7).
 *
 * It answers a form and no script, and it writes three things: the cookie that carries the choice for
 * this browser, the interaction of the journey in progress, when there is one, and the account of
 * whoever is signed in. The three, because they answer three different questions: the cookie is what the
 * next journey of this browser starts in, the interaction is what the next page of this one is read in,
 * which "InteractionLocale::resume()" applies and which would otherwise undo the choice at the following
 * step, and the claim is what this provider writes to that person in when no request of theirs is there
 * to read a language from (UserLocale).
 *
 * It comes back to the page the choice was made on, a path of this origin or the login page, and the
 * language never appears in the URL: a path that carries a locale is a second address for every page.
 */
#[AsController]
final readonly class ChooseLocaleController
{
    public const string ROUTE = 'beffroi_interaction_locale';

    public const string CSRF_TOKEN_ID = 'beffroi_locale';

    public const string PARAMETER = 'locale';

    public const string TARGET_PARAMETER = 'target';

    public function __construct(
        private MessageBusInterface $commandBus,
        private TenantProvider $tenants,
        private ServedLocales $served,
        private BrowserPreferences $preferences,
        private BrowserSession $browser,
        private InteractionRepositoryInterface $interactions,
        private FormToken $formTokens,
    ) {
    }

    #[Route('/locale', name: self::ROUTE, methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        $parameters = RequestParameters::ofBrowserRequest($request);
        $refusal = $this->formTokens->refusal($parameters[FormToken::PARAMETER] ?? null, self::CSRF_TOKEN_ID);
        if ($refusal !== null) {
            return $refusal;
        }
        $response = new RedirectResponse(self::backTo($parameters));
        $asked = $parameters[self::PARAMETER] ?? null;
        $locale = is_string($asked) ? $this->served->match([$asked]) : null;
        // a tag this deployment does not serve changes nothing, and says nothing: the pages carry the
        // languages that have a catalogue, so what asks for another one is not a visitor of them
        if ($locale === null) {
            return $response;
        }
        $response->headers->setCookie($this->preferences->cookie($request, LocalePreference::SLOT, $locale));
        // and on the account of whoever is signed in, which is the claim this provider writes to them in
        // when no request of theirs is there to read a language from (UserLocale, issue #471); on the lane,
        // nothing of this request waiting for it
        $session = $this->browser->authenticationSession($request, $this->tenants->provide());
        if ($session !== null) {
            $this->commandBus->dispatch(new RememberTheChosenLanguage($session->user->id, $locale));
        }
        $id = $parameters[AuthorizationResponder::INTERACTION_PARAMETER] ?? null;
        $interaction = $this->browser->pending($request, $this->tenants->provide(), is_string($id) ? $id : null);
        if ($interaction !== null) {
            $interaction->readIn($locale);
            // written in the request that asks for it, the next page of the journey reading it back
            $this->interactions->save($interaction);
        }

        return $response;
    }

    /**
     * The page the choice was made on, which the form carries, and the login page for anything that is
     * not a path of this origin: a choice of language does not send a browser elsewhere.
     *
     * @param array<string, mixed> $parameters
     */
    private static function backTo(array $parameters): string
    {
        $target = $parameters[self::TARGET_PARAMETER] ?? null;

        return is_string($target) && preg_match('#^/(?![/\\\\])[^\s\\\\]*$#D', $target) === 1 ? $target : '/';
    }
}
