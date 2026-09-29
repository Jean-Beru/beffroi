<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;
use Twig\Error\RuntimeError;

/**
 * Architecture §5.7: the pages of the interaction plane speak the language of the interaction, chosen
 * once on "/authorize" from "ui_locales" (OIDC Core §3.1.2.1), then "Accept-Language", then the default
 * of the deployment, recorded on the interaction and never put in a URL. Every word a user reads comes
 * from the "heidi" catalogue, and a word the catalogue of the language lacks fails the test kernel.
 */
final class LocalizedPagesTest extends BrowserTestCase
{
    private const string ENGLISH_BROWSER = 'en-US,en;q=0.9';

    /**
     * The acceptance criterion of #16: the choice of ui_locales=fr is recorded on the interaction, and
     * the locale is not in the URL.
     */
    #[Test]
    public function uiLocalesFrIsRecordedOnTheInteraction(): void
    {
        // When
        $this->browser->request(
            'GET',
            '/authorize',
            self::authorizationParameters('native-app', [
                'ui_locales' => 'fr',
            ]),
            server: [
                'HTTP_ACCEPT_LANGUAGE' => self::ENGLISH_BROWSER,
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $interaction = self::redirectedInteraction($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'), 'The locale is not in the URL.');
        static::assertSame('fr', $this->storedLocale($interaction));
    }

    /**
     * The acceptance criterion of #16: ui_locales=fr renders the login page in French, whatever the
     * browser now says.
     */
    #[Test]
    public function uiLocalesFrRendersTheLoginPageInFrench(): void
    {
        // Given
        $interaction = $this->frenchInteraction();

        // When
        $crawler = $this->page('/login', $interaction, self::ENGLISH_BROWSER);

        // Then
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Connexion', $crawler->filter('title')->text());
        static::assertSame('Connexion', $crawler->filter('h1')->text());
        static::assertSame('Nom d’utilisateur', $crawler->filter('label[for="username"]')->text());
        static::assertCount(1, $crawler->selectButton('Se connecter'));
    }

    /**
     * A refused login is refused in French.
     */
    #[Test]
    public function aRefusedLoginIsRefusedInTheLanguageOfTheInteraction(): void
    {
        // Given
        self::userWithPassword('alice', 'correct horse battery staple');
        $form = $this->page('/login', $this->frenchInteraction(), self::ENGLISH_BROWSER)->selectButton('Se connecter')->form();
        $form['_username'] = 'alice';
        $form['_password'] = 'wrong';

        // When
        $this->browser->submit($form);
        $crawler = $this->browser->followRedirect();

        // Then
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertStringStartsWith('La connexion a échoué.', $crawler->filter('p[data-error]')->text());
    }

    /**
     * The consent page of the same interaction is French, the browser still asking for English.
     */
    #[Test]
    public function theConsentPageSpeaksTheLanguageOfTheInteraction(): void
    {
        // Given
        $user = self::user('alice');
        $interaction = $this->frenchInteraction();
        $this->signIn($user);
        $this->browser->request(
            'GET',
            '/login',
            [
                'interaction' => $interaction,
            ],
            server: [
                'HTTP_ACCEPT_LANGUAGE' => self::ENGLISH_BROWSER,
            ],
        );
        static::assertSame('/consent?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));

        // When
        $crawler = $this->page('/consent', $interaction, self::ENGLISH_BROWSER);

        // Then
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Autoriser native-app', $crawler->filter('h1')->text());
        static::assertSame('Session ouverte pour alice.', $crawler->filter('main > p')->first()->text());
        static::assertSame(
            ['Qui vous êtes : votre identifiant chez ce fournisseur', 'Votre profil : nom, photo, langue'],
            $crawler->filter('li[data-scope]')->each(static fn (Crawler $scope): string => $scope->text()),
        );
        static::assertCount(1, $crawler->selectButton('Autoriser'));
        static::assertCount(1, $crawler->selectButton('Refuser'));
    }

    /**
     * A ui_locales no enabled locale matches is skipped, not refused (§3.1.2.1 "SHOULD NOT" fail): the
     * browser decides, a regional tag standing for its language.
     */
    #[Test]
    public function acceptLanguageDecidesWhenUiLocalesMatchesNothing(): void
    {
        // When
        $this->browser->request(
            'GET',
            '/authorize',
            self::authorizationParameters('native-app', [
                'ui_locales' => 'de-DE de',
            ]),
            server: [
                'HTTP_ACCEPT_LANGUAGE' => 'fr-CA,fr;q=0.9,en;q=0.5',
            ],
        );

        // Then
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        static::assertSame('fr', $this->storedLocale($interaction));
        $crawler = $this->page('/login', $interaction, 'en');
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Connexion', $crawler->filter('h1')->text());
    }

    /**
     * Nothing asked, nothing matched: the default locale of the deployment.
     */
    #[Test]
    public function theDefaultLocaleWhenNothingMatches(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters(), server: [
            'HTTP_ACCEPT_LANGUAGE' => 'de-DE,de;q=0.9',
        ]);

        // Then
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        static::assertSame('en', $this->storedLocale($interaction));
        $crawler = $this->page('/login', $interaction, 'de-DE,de;q=0.9');
        static::assertSame('en', $crawler->filter('html')->attr('lang'));
        static::assertSame('Sign in', $crawler->filter('h1')->text());
        static::assertSame('native-app asks you to sign in.', $crawler->filter('main > p')->first()->text());
    }

    /**
     * A page shown without an interaction has nothing to record and nothing to read: the error page of
     * a refused request speaks the language of the browser.
     */
    #[Test]
    public function anErrorPageWithoutAnInteractionSpeaksTheLanguageOfTheBrowser(): void
    {
        // When
        $crawler = $this->browser->request(
            'GET',
            '/login',
            [
                'interaction' => 'nothing-this-browser-began',
            ],
            server: [
                'HTTP_ACCEPT_LANGUAGE' => 'fr',
            ],
        );

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Requête refusée', $crawler->filter('h1')->text());
        static::assertSame(AuthorizationResponder::UNKNOWN_INTERACTION, $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame('Aucune requête n’attend cette page. Recommencez depuis l’application.', $crawler->filter('p[data-error]')->text());
        static::assertCount(0, $crawler->filter('p[data-description]'));
    }

    /**
     * RFC 6749 §4.1.2.1: on a refused authorization request the code stays a code and the description
     * of the protocol stays what the developer of the client reads; the explanation is translated.
     */
    #[Test]
    public function aRefusedAuthorizationRequestIsExplainedInTheLanguageOfTheBrowser(): void
    {
        // When
        $crawler = $this->browser->request(
            'GET',
            '/authorize',
            self::authorizationParameters('native-app', [
                'client_id' => 'nobody',
            ]),
            server: [
                'HTTP_ACCEPT_LANGUAGE' => 'fr',
            ],
        );

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('invalid_request', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame(
            'L’application a envoyé une requête que ce fournisseur ne peut pas servir. Recommencez depuis l’application.',
            $crawler->filter('p[data-error]')->text(),
        );
        static::assertSame('invalid_request: The client is unknown.', $crawler->filter('p[data-description]')->text());
    }

    /**
     * RP-Initiated Logout §2: the logout page speaks the "ui_locales" of the logout request, which the
     * confirmation form carries over.
     */
    #[Test]
    public function theLogoutPageSpeaksTheUiLocalesOfTheLogoutRequest(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->frenchLogoutPage();

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Déconnexion', $crawler->filter('h1')->text());
        static::assertSame('fr-FR', $crawler->filter('input[name="ui_locales"]')->attr('value'));
        static::assertStringContainsString('Demo application demande à vous déconnecter.', $crawler->filter('p[data-reason]')->text());
    }

    /**
     * The answer to the confirmation form is read in the same language.
     */
    #[Test]
    public function theAnswerToTheLogoutFormSpeaksTheSameLanguage(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $crawler = $this->frenchLogoutPage();

        // When
        $crawler = $this->browser->submit($crawler->selectButton('Garder la session ouverte')->form());

        // Then
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Session toujours ouverte', $crawler->filter('[data-logged-out="no"]')->text());
    }

    /**
     * Without ui_locales, the browser says, on every request as a browser does.
     */
    #[Test]
    public function withoutUiLocalesTheLogoutPagesSpeakTheLanguageOfTheBrowser(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->browser->setServerParameter('HTTP_ACCEPT_LANGUAGE', 'fr');

        // When
        $crawler = $this->browser->request('GET', '/logout');

        // Then
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame(
            'Votre déconnexion est demandée. Session ouverte pour alice. Voulez-vous vous déconnecter ?',
            $crawler->filter('p[data-reason]')->text(normalizeWhitespace: true),
        );
    }

    #[Test]
    public function withoutUiLocalesTheLoggedOutPageSpeaksTheLanguageOfTheBrowser(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $this->browser->setServerParameter('HTTP_ACCEPT_LANGUAGE', 'fr');
        $crawler = $this->browser->request('GET', '/logout');

        // When
        $crawler = $this->browser->submit($crawler->selectButton('Se déconnecter')->form());

        // Then
        static::assertSame('Session fermée', $crawler->filter('[data-logged-out="yes"]')->text());
    }

    /**
     * The catalogue of every enabled locale defines the keys of the pages, a regional locale falling
     * back on its language.
     */
    #[Test]
    #[DataProvider('provideTranslations')]
    public function theCatalogueTranslatesTheKeysOfThePages(string $locale, string $translation): void
    {
        // Given
        $twig = self::service('twig', Environment::class);

        // When
        $rendered = $twig->createTemplate("{{ 'login.title'|trans({}, 'heidi', '" . $locale . "') }}")->render();

        // Then
        static::assertSame($translation, $rendered);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideTranslations(): iterable
    {
        yield 'en' => ['en', 'Sign in'];
        yield 'fr_CA' => ['fr_CA', 'Connexion'];
    }

    /**
     * The test kernel fails on a missing translation (the acceptance criterion of #16): a key the
     * catalogue of the language does not define is an error, even when the default locale defines it.
     */
    #[Test]
    public function theTestKernelFailsOnAMissingTranslation(): void
    {
        // Given
        $template = self::service('twig', Environment::class)->createTemplate("{{ 'login.nothing'|trans({}, 'heidi', 'fr') }}");

        // When
        try {
            $template->render();
            static::fail('A missing translation was rendered.');
        } catch (RuntimeError $error) {
            // Then
            $cause = $error->getPrevious();
            static::assertInstanceOf(LogicException::class, $cause);
            static::assertSame('No translation of "login.nothing" in the "heidi" domain for the "fr" locale.', $cause->getMessage());
        }
    }

    /**
     * An interaction of the native client asked in French by a browser that speaks English.
     */
    private function frenchInteraction(): string
    {
        $this->browser->request(
            'GET',
            '/authorize',
            self::authorizationParameters('native-app', [
                'ui_locales' => 'fr',
            ]),
            server: [
                'HTTP_ACCEPT_LANGUAGE' => self::ENGLISH_BROWSER,
            ],
        );

        return self::redirectedInteraction($this->browser->getResponse());
    }

    /**
     * The logout page asked in French by oidc-demo, from a browser that speaks English.
     */
    private function frenchLogoutPage(): Crawler
    {
        return $this->browser->request(
            'GET',
            '/logout',
            [
                'client_id' => 'oidc-demo',
                'ui_locales' => 'fr-FR',
            ],
            server: [
                'HTTP_ACCEPT_LANGUAGE' => 'en',
            ],
        );
    }

    private function storedLocale(string $interaction): ?string
    {
        $stored = self::service('test.heidi.interactions', InteractionRepositoryInterface::class)
            ->find($interaction) ?? static::fail('The interaction is gone.');

        return $stored->locale;
    }

    private function page(string $path, string $interaction, string $acceptLanguage): Crawler
    {
        $crawler = $this->browser->request(
            'GET',
            $path,
            [
                'interaction' => $interaction,
            ],
            server: [
                'HTTP_ACCEPT_LANGUAGE' => $acceptLanguage,
            ],
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        // The consent page builds a policy of its own around what the client registered (ConsentPage);
        // the client of this test registered no logo, so it names no origin.
        self::assertInteractionHeaders(
            $response,
            $path === '/consent' ? "img-src 'self'; frame-ancestors 'none'" : self::INTERACTION_POLICY,
        );

        return $crawler;
    }
}
