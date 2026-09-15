<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Unit\Http;

use DateTimeImmutable;
use Heidi\Bundle\Http\InteractionLocale;
use Heidi\Core\Domain\Tenant\Issuer;
use Heidi\Core\Domain\Tenant\Tenant;
use Heidi\Oidc\Domain\Authorization\AuthorizationRequest;
use Heidi\Oidc\Domain\Authorization\CodeChallenge;
use Heidi\Oidc\Domain\Authorization\CodeChallengeMethod;
use Heidi\Oidc\Domain\Client\Client;
use Heidi\Oidc\Domain\Client\RedirectUri;
use Heidi\Oidc\Domain\Client\TokenEndpointAuthMethod;
use Heidi\Oidc\Domain\Interaction\Interaction;
use Heidi\Oidc\Domain\Scope\Scope;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Translation\LocaleSwitcher;
use Symfony\Component\Uid\Uuid;

/**
 * Architecture §5.7: the locale of an interaction is "ui_locales" (OIDC Core §3.1.2.1) matched against
 * the enabled locales, then "Accept-Language", then the default of the deployment; never the URL.
 */
final class InteractionLocaleTest extends TestCase
{
    /**
     * @param list<string> $enabled
     * @param list<string> $uiLocales
     */
    #[Test]
    #[DataProvider('choices')]
    public function theLocaleIsUiLocalesThenAcceptLanguageThenTheDefault(array $enabled, string $default, array $uiLocales, ?string $acceptLanguage, string $expected): void
    {
        $locale = new InteractionLocale(new LocaleSwitcher($default, []), $enabled, $default);
        // Request::create() gives every request an English Accept-Language; the case says which header there is
        $request = Request::create('/authorize');
        $request->headers->remove('Accept-Language');
        if ($acceptLanguage !== null) {
            $request->headers->set('Accept-Language', $acceptLanguage);
        }

        static::assertSame($expected, $locale->choose($request, $uiLocales));
    }

    /**
     * @return iterable<string, array{list<string>, string, list<string>, string|null, string}>
     */
    public static function choices(): iterable
    {
        yield 'the first ui_locales tag an enabled locale matches wins' => [['en', 'fr'], 'en', ['de', 'fr-CA', 'en'], 'en', 'fr'];
        yield 'a region is kept when that locale is enabled' => [['en', 'fr', 'fr_CA'], 'en', ['fr-ca'], null, 'fr_CA'];
        yield 'a region is dropped when only the language is enabled' => [['en', 'fr'], 'en', ['fr-BE'], null, 'fr'];
        yield 'a script subtag is matched before the language alone' => [['en', 'zh_Hant'], 'en', ['zh-Hant-TW'], null, 'zh_Hant'];
        yield 'a tag no locale matches is skipped, not refused' => [['en', 'fr'], 'en', ['xx-YY', 'fr'], null, 'fr'];
        yield 'Accept-Language when ui_locales matches nothing' => [['en', 'fr'], 'en', ['de'], 'fr-FR,fr;q=0.9,en;q=0.8', 'fr'];
        yield 'Accept-Language when there is no ui_locales' => [['en', 'fr'], 'en', [], 'fr-CA', 'fr'];
        yield 'the default when nothing matches' => [['en', 'fr'], 'en', ['de'], 'de-DE,de;q=0.9', 'en'];
        yield 'the default when nothing is asked' => [['en', 'fr'], 'fr', [], null, 'fr'];
        yield 'the default alone when the application enables no locale' => [[], 'en', ['fr'], 'fr', 'en'];
        yield 'a tag that names no language is ignored' => [['en', 'fr'], 'en', ['', '1-2', 'fr'], null, 'fr'];
        yield 'a private use subtag is ignored' => [['en', 'fr'], 'en', ['fr-x-private'], null, 'fr'];
    }

    #[Test]
    public function theEnabledLocalesAreCanonicalAndTheDefaultComesFirst(): void
    {
        $locale = new InteractionLocale(new LocaleSwitcher('fr', []), ['en', 'fr-ca', 'FR', 'zh-hant'], 'fr');

        static::assertSame(['fr', 'en', 'fr_CA', 'zh_Hant'], $locale->enabledLocales());
    }

    /**
     * The request carries the locale for the response, the switcher for everything that translates.
     */
    #[Test]
    public function applyingALocaleSetsItOnTheRequestAndOnTheSwitcher(): void
    {
        $switcher = new LocaleSwitcher('en', []);
        $locale = new InteractionLocale($switcher, ['en', 'fr'], 'en');
        $request = Request::create('/login');

        $locale->apply($request, 'fr');

        static::assertSame('fr', $request->getLocale());
        static::assertSame('fr', $switcher->getLocale());
    }

    #[Test]
    public function aPageOfAnInteractionSpeaksTheLanguageTheInteractionRecorded(): void
    {
        $switcher = new LocaleSwitcher('en', []);
        $locale = new InteractionLocale($switcher, ['en', 'fr'], 'en');
        $request = Request::create('/login');

        $locale->resume($request, self::interaction('fr'));

        static::assertSame('fr', $request->getLocale());
        static::assertSame('fr', $switcher->getLocale());
    }

    #[Test]
    public function anInteractionWithoutALocaleLeavesTheRequestAlone(): void
    {
        $switcher = new LocaleSwitcher('en', []);
        $locale = new InteractionLocale($switcher, ['en', 'fr'], 'en');
        $request = Request::create('/login');
        $request->setLocale('fr');

        $locale->resume($request, self::interaction(null));

        static::assertSame('fr', $request->getLocale());
        static::assertSame('en', $switcher->getLocale());
    }

    /**
     * The listener chooses for the pages of the interaction plane before the controller runs, through
     * the "_locale" attribute the LocaleListener of the kernel reads; the protocol plane and the routes
     * of a host application are not touched.
     */
    #[Test]
    public function theListenerChoosesForTheInteractionPlaneOnly(): void
    {
        $locale = new InteractionLocale(new LocaleSwitcher('en', []), ['en', 'fr'], 'en');

        $page = self::event('heidi_interaction_logout', 'fr');
        $locale->onKernelRequest($page);
        static::assertSame('fr', $page->getRequest()->attributes->get('_locale'));

        $endpoint = self::event('heidi_protocol_token', 'fr');
        $locale->onKernelRequest($endpoint);
        static::assertFalse($endpoint->getRequest()->attributes->has('_locale'));

        $host = self::event('host_route', 'fr');
        $locale->onKernelRequest($host);
        static::assertFalse($host->getRequest()->attributes->has('_locale'));

        $unrouted = self::event(null, 'fr');
        $locale->onKernelRequest($unrouted);
        static::assertFalse($unrouted->getRequest()->attributes->has('_locale'));

        $sub = self::event('heidi_interaction_login', 'fr', HttpKernelInterface::SUB_REQUEST);
        $locale->onKernelRequest($sub);
        static::assertFalse($sub->getRequest()->attributes->has('_locale'));
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
        $client = new Client($tenant, 'native-app', 'Native', TokenEndpointAuthMethod::None, null, [new RedirectUri('http://127.0.0.1/callback')]);
        $request = new AuthorizationRequest(
            $client,
            new RedirectUri('http://127.0.0.1/callback'),
            [Scope::openid()],
            new CodeChallenge('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', CodeChallengeMethod::S256),
            'state',
            'nonce',
        );

        return new Interaction(Interaction::generateId(), $tenant, $request, $locale, $now, $now->modify('+10 minutes'));
    }
}
