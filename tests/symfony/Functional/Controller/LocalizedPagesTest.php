<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use LogicException;
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
    /**
     * The acceptance criterion of #16: ui_locales=fr renders the login page in French. The choice is
     * recorded on the interaction, so the next page is French too, whatever the browser now says.
     */
    #[Test]
    public function uiLocalesFrRendersTheLoginPageInFrench(): void
    {
        $user = self::userWithPassword('alice', 'correct horse battery staple');

        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'ui_locales' => 'fr',
        ]), server: [
            'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $interaction = self::redirectedInteraction($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'), 'The locale is not in the URL.');
        $stored = self::service('test.heidi.interactions', InteractionRepositoryInterface::class)->find($interaction) ?? static::fail('The interaction is gone.');
        static::assertSame('fr', $stored->locale);

        $crawler = $this->page('/login', $interaction, 'en-US,en;q=0.9');
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Connexion', $crawler->filter('title')->text());
        static::assertSame('Connexion', $crawler->filter('h1')->text());
        static::assertSame('Nom d’utilisateur', $crawler->filter('label[for="username"]')->text());
        static::assertCount(1, $crawler->selectButton('Se connecter'));

        // a refused login is refused in French
        $form = $crawler->selectButton('Se connecter')
            ->form();
        $form['_username'] = 'alice';
        $form['_password'] = 'wrong';
        $this->browser->submit($form);
        $crawler = $this->browser->followRedirect();
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertStringStartsWith('La connexion a échoué.', $crawler->filter('p[data-error]')->text());

        // the consent page of the same interaction is French, the browser still asking for English
        $this->signIn($user);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ], server: [
            'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
        ]);
        static::assertSame('/consent?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
        $crawler = $this->page('/consent', $interaction, 'en-US,en;q=0.9');
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Autoriser native-app', $crawler->filter('h1')->text());
        static::assertSame('Session ouverte pour alice.', $crawler->filter('main > p')->first()->text());
        static::assertSame(['Qui vous êtes : votre identifiant chez ce fournisseur', 'Votre profil : nom, photo, langue'], $crawler->filter('li[data-scope]')->each(static fn (Crawler $scope): string => $scope->text()));
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
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'ui_locales' => 'de-DE de',
        ]), server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr-CA,fr;q=0.9,en;q=0.5',
        ]);
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $stored = self::service('test.heidi.interactions', InteractionRepositoryInterface::class)->find($interaction) ?? static::fail('The interaction is gone.');
        static::assertSame('fr', $stored->locale);

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
        $this->browser->request('GET', '/authorize', self::authorizationParameters(), server: [
            'HTTP_ACCEPT_LANGUAGE' => 'de-DE,de;q=0.9',
        ]);
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $stored = self::service('test.heidi.interactions', InteractionRepositoryInterface::class)->find($interaction) ?? static::fail('The interaction is gone.');
        static::assertSame('en', $stored->locale);

        $crawler = $this->page('/login', $interaction, 'de-DE,de;q=0.9');
        static::assertSame('en', $crawler->filter('html')->attr('lang'));
        static::assertSame('Sign in', $crawler->filter('h1')->text());
        static::assertSame('native-app asks you to sign in.', $crawler->filter('main > p')->first()->text());
    }

    /**
     * A page shown without an interaction has nothing to record and nothing to read: the error page of
     * a refused request speaks the language of the browser, the code stays a code and the description
     * of the protocol stays what the developer of the client reads (RFC 6749 §4.1.2.1).
     */
    #[Test]
    public function anErrorPageSpeaksTheLanguageOfTheBrowser(): void
    {
        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => 'nothing-this-browser-began',
        ], server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr',
        ]);
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Requête refusée', $crawler->filter('h1')->text());
        static::assertSame(AuthorizationResponder::UNKNOWN_INTERACTION, $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame('Aucune requête n’attend cette page. Recommencez depuis l’application.', $crawler->filter('p[data-error]')->text());
        static::assertCount(0, $crawler->filter('p[data-description]'));

        $crawler = $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'client_id' => 'nobody',
        ]), server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr',
        ]);
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('invalid_request', $crawler->filter('p[data-error]')->attr('data-error'));
        static::assertSame('L’application a envoyé une requête que ce fournisseur ne peut pas servir. Recommencez depuis l’application.', $crawler->filter('p[data-error]')->text());
        static::assertSame('invalid_request: The client is unknown.', $crawler->filter('p[data-description]')->text());
    }

    /**
     * RP-Initiated Logout §2: the logout pages speak the "ui_locales" of the logout request, which the
     * confirmation form carries over so that the answer is read in the same language; without one, the
     * language of the browser.
     */
    #[Test]
    public function theLogoutPagesSpeakTheUiLocalesOfTheLogoutRequest(): void
    {
        $this->signIn(self::user('alice'));

        $crawler = $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
            'ui_locales' => 'fr-FR',
        ], server: [
            'HTTP_ACCEPT_LANGUAGE' => 'en',
        ]);
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Déconnexion', $crawler->filter('h1')->text());
        static::assertSame('fr-FR', $crawler->filter('input[name="ui_locales"]')->attr('value'));
        static::assertStringContainsString('Demo application demande à vous déconnecter.', $crawler->filter('p[data-reason]')->text());

        $crawler = $this->browser->submit($crawler->selectButton('Garder la session ouverte')->form());
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Session toujours ouverte', $crawler->filter('[data-logged-out="no"]')->text());

        // without ui_locales, the browser says, on every request as a browser does
        $this->browser->setServerParameter('HTTP_ACCEPT_LANGUAGE', 'fr');
        $crawler = $this->browser->request('GET', '/logout');
        static::assertSame('fr', $crawler->filter('html')->attr('lang'));
        static::assertSame('Votre déconnexion est demandée. Session ouverte pour alice. Voulez-vous vous déconnecter ?', $crawler->filter('p[data-reason]')->text(normalizeWhitespace: true));
        $crawler = $this->browser->submit($crawler->selectButton('Se déconnecter')->form());
        static::assertSame('Session fermée', $crawler->filter('[data-logged-out="yes"]')->text());
    }

    /**
     * The test kernel fails on a missing translation (the acceptance criterion of #16): a key the
     * catalogue of the language does not define is an error, even when the default locale defines it.
     */
    #[Test]
    public function theTestKernelFailsOnAMissingTranslation(): void
    {
        $twig = self::service('twig', Environment::class);

        static::assertSame('Sign in', $twig->createTemplate("{{ 'login.title'|trans({}, 'heidi', 'en') }}")->render());
        static::assertSame('Connexion', $twig->createTemplate("{{ 'login.title'|trans({}, 'heidi', 'fr_CA') }}")->render());
        try {
            $twig->createTemplate("{{ 'login.nothing'|trans({}, 'heidi', 'fr') }}")
                ->render();
            static::fail('A missing translation was rendered.');
        } catch (RuntimeError $error) {
            $cause = $error->getPrevious();
            static::assertInstanceOf(LogicException::class, $cause);
            static::assertSame('No translation of "login.nothing" in the "heidi" domain for the "fr" locale.', $cause->getMessage());
        }
    }

    private function page(string $path, string $interaction, string $acceptLanguage): Crawler
    {
        $crawler = $this->browser->request('GET', $path, [
            'interaction' => $interaction,
        ], server: [
            'HTTP_ACCEPT_LANGUAGE' => $acceptLanguage,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        self::assertInteractionHeaders($response);

        return $crawler;
    }
}
