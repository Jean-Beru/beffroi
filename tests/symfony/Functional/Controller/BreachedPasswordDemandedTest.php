<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §5.2
 */
final class BreachedPasswordDemandedTest extends BrowserTestCase
{
    private const string IN_USE = 'correct horse battery staple';

    private const string POSED = 'a horse walks into a bar';

    #[Test]
    public function aLoginThatServesNoAuthorizationRequestLandsOnThePageOfThePassword(): void
    {
        // Given
        self::aPasswordThatWasFound('alice');

        // When
        $this->signInOnTheForm('alice', self::IN_USE);

        // Then
        static::assertSame('/account/password', $this->browser->getResponse()->headers->get('Location'));
    }

    #[Test]
    public function thePageSaysWhyTheBrowserIsThere(): void
    {
        // Given
        self::aPasswordThatWasFound('alice');
        $this->signInOnTheForm('alice', self::IN_USE);

        // When
        $page = $this->browser->followRedirect();

        // Then
        static::assertCount(1, $page->filter('p[data-password-demanded]'));
    }

    #[Test]
    public function thePageSaysNothingOfTheSortToWhoeverWentLookingForIt(): void
    {
        // Given
        $alice = self::aPasswordThatWasFound('alice');
        $this->signIn($alice);

        // When
        $page = $this->passwordPage();

        // Then
        static::assertCount(1, $page->filter('p[data-password-breached]'));
        static::assertCount(0, $page->filter('p[data-password-demanded]'));
    }

    #[Test]
    public function replacingThePasswordSendsThemWhereTheyWereGoing(): void
    {
        // Given
        $alice = self::aPasswordThatWasFound('alice');
        $this->signInOnTheForm('alice', self::IN_USE);

        // When
        $this->change(self::IN_USE, self::POSED);

        // Then
        static::assertSame('/account', $this->browser->getResponse()->headers->get('Location'));
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::POSED));
    }

    #[Test]
    public function aPasswordReplacedIsAskedForNoLongerAtTheNextLogin(): void
    {
        // Given
        self::aPasswordThatWasFound('alice');
        $this->signInOnTheForm('alice', self::IN_USE);
        $this->change(self::IN_USE, self::POSED);
        $this->browser->getCookieJar()->clear();

        // When
        $this->signInOnTheForm('alice', self::POSED);

        // Then
        static::assertSame('/account', $this->browser->getResponse()->headers->get('Location'));
    }

    #[Test]
    public function aPersonWhoLeavesThePageWithoutReplacingItReachesTheirAccount(): void
    {
        // Given
        self::aPasswordThatWasFound('alice');
        $this->signInOnTheForm('alice', self::IN_USE);

        // When
        $this->browser->request('GET', '/account');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    #[Test]
    public function theDemandComesBackAtTheNextSuchLogin(): void
    {
        // Given
        self::aPasswordThatWasFound('alice');
        $this->signInOnTheForm('alice', self::IN_USE);
        $this->browser->request('GET', '/account');
        $this->browser->getCookieJar()->clear();

        // When
        $this->signInOnTheForm('alice', self::IN_USE);

        // Then
        static::assertSame('/account/password', $this->browser->getResponse()->headers->get('Location'));
    }

    #[Test]
    public function theProofOfTheLoginThatWasDivertedOpensThePage(): void
    {
        // Given
        self::aPasswordThatWasFound('alice');
        $this->signInOnTheForm('alice', self::IN_USE);

        // When
        $this->browser->followRedirect();

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
    }

    private static function aPasswordThatWasFound(string $username): User
    {
        $user = self::userWithPassword($username, self::IN_USE);
        $credential = self::passwordOf($user);
        $credential->foundInABreach(self::currentSecond());
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($credential);

        return $user;
    }

    private function signInOnTheForm(string $username, string $password): void
    {
        $this->browser->request('GET', '/account');
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        $this->browser->submit(
            $this->browser
                ->followRedirect()
                ->selectButton('Sign in')
                ->form([
                    '_username' => $username,
                    '_password' => $password,
                ]),
        );
    }

    private function passwordPage(): Crawler
    {
        $page = $this->browser->request('GET', '/account/password');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());

        return $page;
    }

    private function change(string $inUse, string $posed): void
    {
        $token = self::string($this->passwordPage()->filter('form[data-password="change"] input[name="_token"]')->attr('value'));
        $this->browser->request('POST', '/account/password', [
            '_token' => $token,
            'current_password' => $inUse,
            'new_password' => $posed,
            'new_password_again' => $posed,
        ]);
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
}
