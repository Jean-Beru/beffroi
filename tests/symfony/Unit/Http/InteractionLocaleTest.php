<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Unit\Http;

use Beffroi\Oidc\Tests\Fixture\Secrets;
use DateTimeImmutable;
use App\Http\BrowserSession;
use App\Http\BrowserPreferences;
use App\Locale\LocalePreference;
use App\Locale\UserLocale;
use App\Tests\Symfony\Fixture\AmbientTenant;
use Beffroi\Core\Bridge\InMemory\InMemoryAuthenticationSessionRepository;
use Beffroi\Oidc\Bridge\InMemory\InMemoryInteractionRepository;
use Symfony\Component\Clock\MockClock;
use App\Http\InteractionLocale;
use App\Locale\ServedLocales;
use Beffroi\Core\Domain\Tenant\Issuer;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Oidc\Domain\Scope\Scopes;
use Beffroi\Oidc\Domain\Authorization\AuthorizationRequest;
use Beffroi\Oidc\Domain\Authorization\CodeChallenge;
use Beffroi\Oidc\Domain\Authorization\Sha256CodeChallengeMethod;
use Beffroi\Oidc\Domain\Client\Client;
use Beffroi\Oidc\Domain\Client\ClientPresentation;
use Beffroi\Oidc\Domain\Client\ClientRegistration;
use Beffroi\Oidc\Domain\Client\RedirectUri;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Domain\Scope\Scope;
use Beffroi\Oidc\Tests\Fixture\Methods;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Translation\LocaleSwitcher;
use Symfony\Component\Uid\Uuid;
use Beffroi\Oidc\Tests\Fixture\Shapes;

/**
 * Architecture §5.7: the locale of an interaction is what the visitor asked for (issue #448), then
 * "ui_locales" (OIDC Core §3.1.2.1), then "Accept-Language", then the default, each read against the
 * locales this deployment serves; never the URL. How a tag is read against that list is ServedLocales and
 * is tested there, and what the cookie of the preferences holds is BrowserPreferencesTest.
 */
final class InteractionLocaleTest extends TestCase
{
    /**
     * @param list<string> $enabled
     * @param list<string> $uiLocales
     */
    #[Test]
    #[DataProvider('provideChoices')]
    public function theLocaleIsUiLocalesThenAcceptLanguageThenTheDefault(
        array $enabled,
        string $default,
        array $uiLocales,
        ?string $acceptLanguage,
        string $expected,
    ): void {
        // Given
        $locale = self::locale(new LocaleSwitcher($default, []), new ServedLocales($enabled, $default));
        // Request::create() gives every request an English Accept-Language; the case says which header there is
        $request = Request::create('/authorize');
        $request->headers->remove('Accept-Language');
        if ($acceptLanguage !== null) {
            $request->headers->set('Accept-Language', $acceptLanguage);
        }

        // When / Then
        static::assertSame($expected, $locale->choose($request, $uiLocales));
    }

    /**
     * @return iterable<string, array{list<string>, string, list<string>, string|null, string}>
     */
    public static function provideChoices(): iterable
    {
        yield 'ui_locales, before the header' => [['en', 'fr'], 'en', ['fr'], 'en', 'fr'];
        yield 'Accept-Language when ui_locales matches nothing' => [['en', 'fr'], 'en', ['de'], 'fr-FR,fr;q=0.9,en;q=0.8', 'fr'];
        yield 'Accept-Language when there is no ui_locales' => [['en', 'fr'], 'en', [], 'fr-CA', 'fr'];
        yield 'the default when nothing matches' => [['en', 'fr'], 'en', ['de'], 'de-DE,de;q=0.9', 'en'];
        yield 'the default when nothing is asked' => [['en', 'fr'], 'fr', [], null, 'fr'];
        yield 'the default alone when the application serves no other locale' => [[], 'en', ['fr'], 'fr', 'en'];
    }

    /**
     * The request carries the locale for the response, the switcher for everything that translates.
     */
    #[Test]
    public function whatTheVisitorChoseOutranksTheHintOfTheClient(): void
    {
        // Given
        $served = new ServedLocales(['en', 'fr'], 'en');
        $locale = self::locale(new LocaleSwitcher('en', []), $served);
        $request = Request::create('/authorize');
        $request->headers->set('Accept-Language', 'en');
        $request->cookies->set(BrowserPreferences::COOKIE, 'locale=fr');

        // When / Then
        static::assertSame('fr', $locale->choose($request, ['en']));
    }

    #[Test]
    public function aChoiceThisDeploymentDoesNotServeLeavesTheHintInPlace(): void
    {
        // Given
        $served = new ServedLocales(['en', 'fr'], 'en');
        $locale = self::locale(new LocaleSwitcher('en', []), $served);
        $request = Request::create('/authorize');
        $request->cookies->set(BrowserPreferences::COOKIE, 'locale=de');

        // When / Then
        static::assertSame('fr', $locale->choose($request, ['fr']));
    }

    #[Test]
    public function applyingALocaleSetsItOnTheRequestAndOnTheSwitcher(): void
    {
        // Given
        $switcher = new LocaleSwitcher('en', []);
        $locale = self::locale($switcher, new ServedLocales(['en', 'fr'], 'en'));
        $request = Request::create('/login');

        // When
        $locale->apply($request, 'fr');

        // Then
        static::assertSame('fr', $request->getLocale());
        static::assertSame('fr', $switcher->getLocale());
    }

    #[Test]
    public function aPageOfAnInteractionSpeaksTheLanguageTheInteractionRecorded(): void
    {
        // Given
        $switcher = new LocaleSwitcher('en', []);
        $locale = self::locale($switcher, new ServedLocales(['en', 'fr'], 'en'));
        $request = Request::create('/login');

        // When
        $locale->resume($request, self::interaction('fr'));

        // Then
        static::assertSame('fr', $request->getLocale());
        static::assertSame('fr', $switcher->getLocale());
    }

    #[Test]
    public function anInteractionWithoutALocaleLeavesTheRequestAlone(): void
    {
        // Given
        $switcher = new LocaleSwitcher('en', []);
        $locale = self::locale($switcher, new ServedLocales(['en', 'fr'], 'en'));
        $request = Request::create('/login');
        $request->setLocale('fr');

        // When
        $locale->resume($request, self::interaction(null));

        // Then
        static::assertSame('fr', $request->getLocale());
        static::assertSame('en', $switcher->getLocale());
    }

    /**
     * The listener chooses for the pages of the interaction plane before the controller runs, through
     * the "_locale" attribute the LocaleListener of the kernel reads; the protocol plane and the routes
     * of the application outside the two planes are not touched.
     */
    #[Test]
    public function theListenerChoosesForThePagesOfTheInteractionPlane(): void
    {
        // Given
        $locale = self::locale(new LocaleSwitcher('en', []), new ServedLocales(['en', 'fr'], 'en'));
        $page = self::event('beffroi_interaction_logout', 'fr');

        // When
        $locale->onKernelRequest($page);

        // Then
        static::assertSame('fr', $page->getRequest()->attributes->get('_locale'));
    }

    #[Test]
    #[DataProvider('provideRequestsOutsideTheInteractionPlane')]
    public function theListenerLeavesTheOtherRequestsAlone(?string $route, int $type): void
    {
        // Given
        $locale = self::locale(new LocaleSwitcher('en', []), new ServedLocales(['en', 'fr'], 'en'));
        $event = self::event($route, 'fr', $type);

        // When
        $locale->onKernelRequest($event);

        // Then
        static::assertFalse($event->getRequest()->attributes->has('_locale'));
    }

    /**
     * @return iterable<string, array{?string, int}>
     */
    public static function provideRequestsOutsideTheInteractionPlane(): iterable
    {
        yield 'the protocol plane' => ['beffroi_protocol_token', HttpKernelInterface::MAIN_REQUEST];
        yield 'a route of the application' => ['host_route', HttpKernelInterface::MAIN_REQUEST];
        yield 'no route' => [null, HttpKernelInterface::MAIN_REQUEST];
        yield 'a sub request of the interaction plane' => ['beffroi_interaction_login', HttpKernelInterface::SUB_REQUEST];
    }

    private static function event(?string $route, string $acceptLanguage, int $type = HttpKernelInterface::MAIN_REQUEST): RequestEvent
    {
        $request = Request::create('/');
        $request->headers->set('Accept-Language', $acceptLanguage);
        if ($route !== null) {
            $request->attributes->set('_route', $route);
        }

        return new RequestEvent(static::createStub(HttpKernelInterface::class), $request, $type);
    }

    private static function interaction(?string $locale): Interaction
    {
        $now = new DateTimeImmutable('2026-09-15T10:00:00+00:00');
        $tenant = new Tenant(Uuid::v7(), 'default', new Issuer('https://op.test'), 'OP', $now);
        $client = new Client(
            $tenant,
            new ClientRegistration(
                'native-app',
                new ClientPresentation('Native'),
                Methods::none(),
                false,
                [new RedirectUri('http://127.0.0.1/callback')],
                Shapes::jwt(),
            ),
        );
        $request = new AuthorizationRequest(
            $client,
            new RedirectUri('http://127.0.0.1/callback'),
            new Scopes([Scope::openid()]),
            new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', new Sha256CodeChallengeMethod()),
            'state',
            'nonce',
        );

        return new Interaction(Secrets::draw(), $tenant, $request, $locale, $now, $now->modify('+10 minutes'));
    }

    /**
     * No session of the core and no tenant: what this reads of a visitor nobody knows (issue #485), which
     * is every case below. What a page of somebody who is signed in speaks is played where a session
     * exists, in the functional suite.
     */
    private static function locale(LocaleSwitcher $switcher, ServedLocales $served): InteractionLocale
    {
        return new InteractionLocale(
            $switcher,
            $served,
            new BrowserPreferences([new LocalePreference($served)]),
            new BrowserSession(new InMemoryAuthenticationSessionRepository(), new InMemoryInteractionRepository(), new MockClock()),
            new AmbientTenant(null),
            new UserLocale($served),
        );
    }
}
