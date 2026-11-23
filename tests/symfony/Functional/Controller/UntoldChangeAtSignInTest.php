<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Event\CredentialChangeNotTold;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Journal\JournalEntry;
use Beffroi\Core\Port\JournalInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\Clock\Clock;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * NIST SP 800-63B-4 §4.6
 */
final class UntoldChangeAtSignInTest extends BrowserTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    #[Test]
    public function aChangeNotNotifiedSinceThePreviousSignInIsToldAtTheSignInThatFollowsIt(): void
    {
        // Given
        $interaction = $this->signedInAfter(self::untoldSinceThePreviousSignIn());

        // When
        $crawler = $this->browser->request('GET', '/login', ['interaction' => $interaction]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertCount(1, $crawler->filter('[data-untold-change]'));
    }

    #[Test]
    public function theRequestGoesOnOnceTheChangeIsTold(): void
    {
        // Given
        $interaction = $this->signedInAfter(self::untoldSinceThePreviousSignIn());
        $continue = $this->browser->request('GET', '/login', ['interaction' => $interaction])->selectButton('Continue')->form();

        // When
        $this->browser->request('GET', $continue->getUri());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));
    }

    #[Test]
    public function aChangeNotNotifiedBeforeThePreviousSignInIsNotToldAgain(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::PASSWORD);
        self::record($alice, CredentialChangeNotTold::NAME);
        self::aSecondLater();
        self::record($alice, UserAuthenticated::NAME);
        self::aSecondLater();
        $interaction = $this->signedInAfter($alice);

        // When
        $this->browser->request('GET', '/login', ['interaction' => $interaction]);

        // Then
        static::assertSame('/consent?interaction=' . $interaction, $this->browser->getResponse()->headers->get('Location'));
    }

    /**
     * OIDC Core §3.1.2.1
     */
    #[Test]
    public function aRequestWithPromptNoneIsAnsweredAtItsRedirectionUriWithoutTheNotice(): void
    {
        // Given
        $this->signIn(self::untoldSinceThePreviousSignIn(), Clock::get()->now());

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters(parameters: ['prompt' => 'none']));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertStringStartsWith('http://127.0.0.1/callback?', (string) $response->headers->get('Location'));
    }

    #[Test]
    public function aChangeNotNotifiedSinceThePreviousSignInIsToldOnTheAccount(): void
    {
        // Given
        $this->signIn(self::untoldSinceThePreviousSignIn(), Clock::get()->now());

        // When
        $crawler = $this->browser->request('GET', '/account');

        // Then
        static::assertCount(1, $crawler->filter('[data-untold-change]'));
    }

    #[Test]
    public function theAccountTellsTheChangeOnce(): void
    {
        // Given
        $this->signIn(self::untoldSinceThePreviousSignIn(), Clock::get()->now());
        $this->browser->request('GET', '/account');

        // When
        $crawler = $this->browser->request('GET', '/account');

        // Then
        static::assertCount(0, $crawler->filter('[data-untold-change]'));
    }

    private static function untoldSinceThePreviousSignIn(): User
    {
        $alice = self::userWithPassword('alice', self::PASSWORD);
        self::record($alice, UserAuthenticated::NAME);
        self::aSecondLater();
        self::record($alice, CredentialChangeNotTold::NAME);
        self::aSecondLater();

        return $alice;
    }

    /**
     * @return string the interaction the person signed in for
     */
    private function signedInAfter(User $user): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $form = $this->browser->request('GET', '/login', ['interaction' => $interaction])->selectButton('Sign in')->form();
        $form['_username'] = $user->username;
        $form['_password'] = self::PASSWORD;
        $this->browser->submit($form);

        return $interaction;
    }

    private static function record(User $user, string $act): void
    {
        self::service('test.beffroi.journal', JournalInterface::class)
            ->record(new JournalEntry(
                Uuid::v7(),
                $user->tenant,
                $act,
                Clock::get()->now(),
                self::context(Clock::get()->now()),
                $user->subject,
            ));
    }
}
