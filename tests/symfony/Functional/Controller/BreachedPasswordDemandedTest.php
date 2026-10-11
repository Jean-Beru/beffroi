<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #579, architecture §5.2: a person whose password a list of compromised passwords has found is
 * asked to replace it at the next login that serves no authorization request. Being told on the pages of
 * their account is issue #552; this is the one step there is between a login and what it was for.
 *
 * The mark is written here rather than played, the lane that writes it being what
 * BreachedPasswordAtLoginTest covers: what this walks is what a login does with a mark that is already
 * there. The list of this kernel names nothing (config_test.yml), so no test here reaches a host.
 */
final class BreachedPasswordDemandedTest extends BrowserTestCase
{
    private const string IN_USE = 'correct horse battery staple';

    private const string POSED = 'a horse walks into a bar';

    /**
     * The one login this interrupts: the one a page of this provider asked for, which is the login a
     * browser that typed the issuer makes.
     */
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

    /**
     * A person is told why they are there rather than on the page they asked for, which is what this adds
     * to a page that already says what was found.
     */
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

    /**
     * A person who went looking for the page reads what was found and nothing that was asked of them: the
     * sentence says why that browser is there, so it is said to a browser a login sent there.
     */
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

    /**
     * Replacing it carries the browser on to the page the login was going to, which stayed remembered
     * while the password was asked for.
     */
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

    /**
     * The mark is what the demand reads, so a password replaced ends it by construction: the credential
     * says nothing of a list any more, that list having spoken of the password that is gone.
     */
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

    /**
     * It is asked and never imposed: somebody who cannot replace their password now reaches their account
     * all the same, or nothing of the account is reachable to the person who most needs it.
     */
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

    /**
     * What leaving the page costs: the demand comes back at the next login that serves no authorization
     * request, which is the point.
     */
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

    /**
     * A page of the account that asks for a proof given a short while ago is reached with the one this
     * login just gave (issue #580): the demand lands on a page nothing sends the browser away from.
     */
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

    /**
     * A password marked as found, on a user who is signed in through the form of the firewall.
     */
    private static function aPasswordThatWasFound(string $username): User
    {
        $user = self::userWithPassword($username, self::IN_USE);
        $credential = self::passwordOf($user);
        $credential->foundInABreach(self::currentSecond());
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($credential);

        return $user;
    }

    /**
     * Signs the user in on the login the home of the account asks for, which serves no authorization
     * request.
     */
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
