<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use App\Http\AuthorizationResponder;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;
use Twig\Error\RuntimeError;

/**
 * Architecture §5.7, OIDC Core §3.1.2.1
 */
final class LocalizedPagesTest extends BrowserTestCase
{
    private const string ENGLISH_BROWSER = 'en-US,en;q=0.9';

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
        static::assertSame('Nom d\'utilisateur', $crawler->filter('label[for="username"]')->text());
        static::assertCount(1, $crawler->selectButton('Se connecter'));
    }

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
        static::assertSame('Nom d\'utilisateur ou mot de passe incorrect.', $crawler->filter('p[data-error]')->text());
    }

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
            ['Votre identifiant', 'Votre profil : nom, photo, langue'],
            $crawler->filter('li[data-scope]')->each(static fn (Crawler $scope): string => $scope->text()),
        );
        static::assertCount(1, $crawler->selectButton('Autoriser'));
        static::assertCount(1, $crawler->selectButton('Refuser'));
    }

    /**
     * OIDC Core §3.1.2.1
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
        static::assertSame('Sign in to continue to native-app.', $crawler->filter('main > p')->first()->text());
    }

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
        static::assertSame('Impossible de continuer', $crawler->filter('h1')->text());
        static::assertSame(AuthorizationResponder::UNKNOWN_INTERACTION, $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame('Cette demande est introuvable. Recommencez depuis l\'application.', $crawler->filter('p[data-error]')->text());
        static::assertCount(0, $crawler->filter('p[data-description]'));
    }

    /**
     * RFC 6749 §4.1.2.1
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
            'L\'application a envoyé une demande invalide. Recommencez depuis l\'application.',
            $crawler->filter('p[data-error]')->text(),
        );
        static::assertSame('invalid_request: The client is unknown.', $crawler->filter('p[data-description]')->text());
    }

    /**
     * RP-Initiated Logout §2
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
            'Session ouverte pour alice. Voulez-vous vous déconnecter ?',
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

    #[Test]
    #[DataProvider('provideTranslations')]
    public function theCatalogueTranslatesTheKeysOfThePages(string $locale, string $translation): void
    {
        // Given
        $twig = self::service('twig', Environment::class);

        // When
        $rendered = $twig->createTemplate("{{ 'login.title'|trans({}, 'beffroi', '" . $locale . "') }}")->render();

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

    #[Test]
    public function theTestKernelFailsOnAMissingTranslation(): void
    {
        // Given
        $template = self::service('twig', Environment::class)->createTemplate("{{ 'login.nothing'|trans({}, 'beffroi', 'fr') }}");

        // When
        try {
            $template->render();
            static::fail('A missing translation was rendered.');
        } catch (RuntimeError $error) {
            // Then
            $cause = $error->getPrevious();
            static::assertInstanceOf(LogicException::class, $cause);
            static::assertSame('No translation of "login.nothing" in the "beffroi" domain for the "fr" locale.', $cause->getMessage());
        }
    }

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
        $stored = self::service('test.beffroi.interactions', InteractionRepositoryInterface::class)
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
        self::assertInteractionHeaders($response);

        return $crawler;
    }
}
