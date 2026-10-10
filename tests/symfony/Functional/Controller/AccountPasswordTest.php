<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Event\PasswordChanged;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §5.2: a person replaces their own password from the page of their account, by typing the
 * one in use first, and every other browser signed in as them is signed out.
 */
final class AccountPasswordTest extends BrowserTestCase
{
    private const string IN_USE = 'correct horse battery staple';

    private const string POSED = 'a horse walks into a bar';

    #[Test]
    public function thePageNeedsASessionOfTheCore(): void
    {
        // When
        $this->browser->request('GET', '/account/password');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Nothing visible changes when a password does, so the date is what the page has to show.
     */
    #[Test]
    public function thePageSaysWhenThePasswordWasLastWritten(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));

        // When
        $page = $this->passwordPage();

        // Then
        static::assertCount(1, $page->filter('p[data-password] time'));
        static::assertCount(1, $page->filter('form[data-password="change"]'));
    }

    #[Test]
    public function thePasswordPosedIsTheOneHeldAfterwards(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);

        // When
        $this->change(self::IN_USE, self::POSED);

        // Then
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::POSED));
        static::assertCount(1, self::events(PasswordChanged::class));
    }

    /**
     * A password is replaced because the one before it is not trusted any more, and a session opened
     * under it is exactly what should not outlive it. The browser it was asked from stays signed in.
     */
    #[Test]
    public function replacingThePasswordSignsEveryOtherBrowserOut(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $current = $this->signIn($alice);
        $elsewhere = self::session($alice, self::currentSecond()->modify('-1 hour'));

        // When
        $this->change(self::IN_USE, self::POSED);

        // Then
        static::assertTrue(self::reread($elsewhere)->hasEnded());
        static::assertFalse(self::reread($current)->hasEnded());
    }

    /**
     * A session somebody else took over does not get to replace the password it signed in with.
     */
    #[Test]
    public function aPasswordInUseThatWasNotTypedIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);

        // When
        $this->change('not the password', self::POSED);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="wrong_password"]'));
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    #[Test]
    public function aPasswordPosedThatIsTheOneHeldIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));

        // When
        $this->change(self::IN_USE, self::IN_USE);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="same_as_before"]'));
    }

    /**
     * What a password has to be is checked on the server, whatever a form said: the page says the floor.
     */
    #[Test]
    public function aPasswordPosedThatIsTooShortIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));

        // When
        $this->browser->request('POST', '/account/password', [
            '_token' => $this->token(),
            'current_password' => self::IN_USE,
            'new_password' => 'short',
        ]);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="not_a_password"]'));
    }

    /**
     * Somebody who signs in by another means has nothing to replace, and is offered no form.
     */
    #[Test]
    public function aPersonWhoHoldsNoPasswordIsOfferedNoForm(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->passwordPage();

        // Then
        static::assertCount(1, $page->filter('p[data-password="none"]'));
        static::assertCount(0, $page->filter('form[data-password="change"]'));
    }

    #[Test]
    public function changingThePasswordWithoutTheTokenOfItsFormIsRefused(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);

        // When
        $this->browser->request('POST', '/account/password', [
            'current_password' => self::IN_USE,
            'new_password' => self::POSED,
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    private function passwordPage(): Crawler
    {
        $page = $this->browser->request('GET', '/account/password');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());

        return $page;
    }

    private function change(string $inUse, string $posed): void
    {
        $this->browser->request('POST', '/account/password', [
            '_token' => $this->token(),
            'current_password' => $inUse,
            'new_password' => $posed,
        ]);
    }

    private function token(): string
    {
        return self::string($this->passwordPage()->filter('form[data-password="change"] input[name="_token"]')->attr('value'));
    }

    private static function hasher(): PasswordHasherInterface
    {
        return self::service('test.beffroi.password_hasher', PasswordHasherInterface::class);
    }

    private static function passwordOf(User $user): PasswordCredential
    {
        self::reload();
        $reread = self::service('test.beffroi.users', UserRepositoryInterface::class)->find($user->id) ?? static::fail('The user is gone.');
        $password = self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->findByUser($reread, PasswordCredential::class)[0] ?? null;
        static::assertInstanceOf(PasswordCredential::class, $password);

        return $password;
    }

    private static function reread(AuthenticationSession $session): AuthenticationSession
    {
        $reread = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $reread);

        return $reread;
    }
}
