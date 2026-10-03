<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Bundle\Http\ChosenLocale;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\Fixtures;
use Beffroi\Oidc\Domain\Interaction\Interaction;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use function array_filter;
use function array_values;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #448, architecture §5.7: a visitor asks the pages to be read in a language this deployment serves.
 * The choice is kept for their browser and recorded on the journey in progress, and it never appears in a
 * URL. What the choice does to the order the language is read in is InteractionLocaleTest.
 */
final class LocaleChoiceTest extends BrowserTestCase
{
    #[Test]
    public function theControlOffersEveryLanguageTheDeploymentServes(): void
    {
        // When
        $page = $this->loginPage();

        // Then
        static::assertSame(['en', 'fr'], $page->filter('form[data-locale="choice"] button[name="locale"]')->extract(['data-locale']));
    }

    #[Test]
    public function aChoiceIsKeptForTheBrowserThatMadeIt(): void
    {
        // Given
        $token = $this->token();
        $interaction = $this->beginInteraction(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // When
        $this->browser->request('POST', '/locale', [
            '_token' => $token,
            'locale' => 'fr',
            'target' => '/login?interaction=' . $interaction->id,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/login?interaction=' . $interaction->id, $response->headers->get('Location'));
        static::assertSame('fr', self::chosenIn($response));
    }

    #[Test]
    public function aChoiceIsRecordedOnTheJourneyInProgress(): void
    {
        // Given
        $token = $this->token();
        $interaction = $this->beginInteraction(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // When
        $this->browser->request('POST', '/locale', [
            '_token' => $token,
            'locale' => 'fr',
            'target' => '/login?interaction=' . $interaction->id,
            'interaction' => $interaction->id,
        ]);

        // Then
        static::assertSame('fr', self::reread($interaction)->locale);
    }

    #[Test]
    #[DataProvider('provideTagsNobodyServes')]
    public function aLanguageThisDeploymentDoesNotServeChangesNothing(string $asked): void
    {
        // Given
        $token = $this->token();
        $interaction = $this->beginInteraction(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // When
        $this->browser->request('POST', '/locale', [
            '_token' => $token,
            'locale' => $asked,
            'target' => '/login?interaction=' . $interaction->id,
            'interaction' => $interaction->id,
        ]);

        // Then
        static::assertNull(self::chosenIn($this->browser->getResponse()));
        static::assertNull(self::reread($interaction)->locale);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideTagsNobodyServes(): iterable
    {
        yield 'another language' => ['de'];
        yield 'not a language' => ['../etc/passwd'];
        yield 'nothing' => [''];
    }

    #[Test]
    public function aTargetOfAnotherOriginComesBackToTheRoot(): void
    {
        // Given
        $token = $this->token();
        $this->beginInteraction(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // When
        $this->browser->request('POST', '/locale', [
            '_token' => $token,
            'locale' => 'fr',
            'target' => '//elsewhere.test/callback',
        ]);

        // Then
        static::assertSame('/', $this->browser->getResponse()->headers->get('Location'));
    }

    #[Test]
    public function aChoiceWithoutTheTokenOfItsFormIsRefused(): void
    {
        // Given
        $this->loginPage();
        $interaction = $this->beginInteraction(Fixtures::now(), Fixtures::now()->modify('+10 minutes'));

        // When
        $this->browser->request('POST', '/locale', [
            'locale' => 'fr',
            'target' => '/login?interaction=' . $interaction->id,
            'interaction' => $interaction->id,
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertNull(self::chosenIn($this->browser->getResponse()));
        static::assertNull(self::reread($interaction)->locale);
    }

    /**
     * Issue #471: a person who is signed in has told this provider which language they read, and the
     * claim of their account is what it writes to them in when no request of theirs is there to read one
     * from (UserLocale).
     */
    /**
     * Issue #485: a page of somebody who is signed in speaks the language their record names, whatever
     * their browser asks for, and nothing is offered to them to choose: they change it where the record
     * is changed (§5.2).
     */
    #[Test]
    public function aPageOfSomebodySignedInSpeaksTheLanguageTheirRecordNames(): void
    {
        // Given
        $alice = self::user('alice');
        $alice->updateProfile($alice->profile->readIn('fr'), self::currentSecond());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);
        $this->signIn($alice);

        // When
        $page = $this->browser->request('GET', '/account', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9',
        ]);

        // Then
        static::assertSame('fr', $page->filter('html')->attr('lang'));
        static::assertCount(0, $page->filter('form[data-locale="choice"]'));
    }

    /**
     * Issue #485: and a record that names no language leaves the chain of a visitor nobody knows in
     * place, which is most people, so the control is there for them.
     */
    #[Test]
    public function aRecordThatNamesNoLanguageLeavesTheBrowserToAnswer(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->browser->request('GET', '/account', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9',
        ]);

        // Then
        static::assertSame('fr', $page->filter('html')->attr('lang'));
        static::assertCount(1, $page->filter('form[data-locale="choice"]'));
    }

    /**
     * Issue #485: a language the record names that this deployment does not serve changes nothing, as it
     * changes nothing anywhere else.
     */
    #[Test]
    public function aLanguageTheRecordNamesAndNobodyServesChangesNothing(): void
    {
        // Given
        $alice = self::user('alice');
        $alice->updateProfile($alice->profile->readIn('ja'), self::currentSecond());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($alice);
        $this->signIn($alice);

        // When
        $page = $this->browser->request('GET', '/account', server: [
            'HTTP_ACCEPT_LANGUAGE' => 'fr-FR,fr;q=0.9',
        ]);

        // Then
        static::assertSame('fr', $page->filter('html')->attr('lang'));
        static::assertCount(1, $page->filter('form[data-locale="choice"]'));
    }

    #[Test]
    public function aChoiceMadeBySomebodySignedInIsWrittenOnTheirAccount(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $token = $this->token();

        // When
        $this->browser->request('POST', '/locale', [
            '_token' => $token,
            'locale' => 'fr',
            'target' => '/account',
        ]);

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertSame('fr', self::rereadUser($alice)->profile->locale);
    }

    #[Test]
    public function aChoiceMadeBySomebodySignedInAsNobodyIsWrittenOnNoAccount(): void
    {
        // Given
        $alice = self::user('alice');
        $token = $this->token();

        // When
        $this->browser->request('POST', '/locale', [
            '_token' => $token,
            'locale' => 'fr',
            'target' => '/login',
        ]);

        // Then
        static::assertSame('fr', self::chosenIn($this->browser->getResponse()));
        static::assertNull(self::rereadUser($alice)->profile->locale);
    }

    private static function rereadUser(User $user): User
    {
        $reread = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id);
        static::assertInstanceOf(User::class, $reread);

        return $reread;
    }

    private function loginPage(): Crawler
    {
        return $this->browser->request('GET', '/login');
    }

    /**
     * The token of the form, read from a page asked before the journey is written: the session this page
     * establishes is the one the pending interaction lands in, and the token is bound to it.
     */
    private function token(): string
    {
        return self::string($this->loginPage()->filter('form[data-locale="choice"] input[name="_token"]')->attr('value'));
    }

    private static function reread(Interaction $interaction): Interaction
    {
        $reread = self::service('test.beffroi.interactions', InteractionRepositoryInterface::class)->find($interaction->id);
        static::assertInstanceOf(Interaction::class, $reread);

        return $reread;
    }

    private static function chosenIn(Response $response): ?string
    {
        $cookies = array_values(array_filter(
            $response->headers->getCookies(),
            static fn (Cookie $cookie): bool => $cookie->getName() === ChosenLocale::COOKIE,
        ));

        return $cookies === [] ? null : $cookies[0]->getValue();
    }
}
