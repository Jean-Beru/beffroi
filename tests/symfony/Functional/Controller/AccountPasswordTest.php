<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use DateInterval;
use Beffroi\Bundle\Http\RecentLogin;
use Beffroi\Core\Domain\Credential\PasswordCredential;
use Beffroi\Core\Domain\Credential\PlainPassword;
use Beffroi\Core\Domain\Event\PasswordChanged;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Core\Port\CredentialRepositoryInterface;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\BreachedPasswordsOfARecord;
use function json_decode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §5.2: a person replaces their own password from the page of their account, by proving who
 * they are a short while ago, typing the one in use, and posing another twice; every other browser signed
 * in as them is signed out.
 *
 * The list of compromised passwords of this kernel is a fixture that names nothing until a test names one
 * (config_test.yml): no test here reaches a host, and what is tested is the rule that reads the answer.
 */
final class AccountPasswordTest extends BrowserTestCase
{
    private const string IN_USE = 'correct horse battery staple';

    private const string POSED = 'a horse walks into a bar';

    private const string BREACHED = 'monkey business as usual';

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
     * What a password has to be is checked on the server, whatever a form said and whatever the meter in
     * the browser showed, and the page says which rule pronounced it. A browser running no script at all
     * posts through the same form and meets the same rules, which is what this does.
     */
    #[Test]
    #[DataProvider('providePasswordsThatAreNoPassword')]
    public function aPasswordPosedThatIsNoPasswordIsRefusedAndSaidOnThePage(string $posed, string $error): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));

        // When
        $this->change(self::IN_USE, $posed);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="' . $error . '"]'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function providePasswordsThatAreNoPassword(): iterable
    {
        yield 'shorter than eight characters' => ['short', 'too_short'];
        yield 'a word and a digit' => ['password1', 'too_weak'];
    }

    /**
     * A password nobody can read back is a password nobody can check they typed right, and somebody who
     * mistypes it has lost the account rather than changed it.
     */
    #[Test]
    public function aPasswordPosedTwiceAndTypedDifferentlyIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);

        // When
        $this->change(self::IN_USE, self::POSED, self::POSED . '!');

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="not_confirmed"]'));
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    /**
     * The rule NIST SP 800-63B §5.1.1.2 puts first, on this page: the page refuses the two the console
     * refuses.
     */
    #[Test]
    public function aPasswordAListCountsIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        self::breaches()->names([self::BREACHED]);

        // When
        $this->change(self::IN_USE, self::BREACHED);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="breached"]'));
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    /**
     * Decision 0006: an unknown is not a clean answer. Nothing is written and the page says so.
     */
    #[Test]
    public function aPasswordNoListCouldBeAskedAboutIsRefusedAndSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        self::breaches()->cannotBeReached();

        // When
        $this->change(self::IN_USE, self::POSED);

        // Then
        static::assertCount(1, $this->afterTheForm()->filter('p[data-error="not_checked"]'));
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    /**
     * A deployment that names no list poses passwords all the same, which is every other test here.
     */
    #[Test]
    public function aDeploymentThatNamesNoListPosesThePasswordAllTheSame(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        self::breaches()->namesNothing();

        // When
        $this->change(self::IN_USE, self::BREACHED);

        // Then
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::BREACHED));
        static::assertSame([], self::breaches()->asked);
    }

    /**
     * A session is not a proof of presence: this is the form somebody else would use to lock its owner
     * out of their account, so the proof is asked again at the login of the firewall.
     */
    #[Test]
    public function aSessionThatProvedNothingRecentlyIsSentToTheLogin(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE), self::currentSecond()->modify('-1 hour'));

        // When
        $this->browser->request('GET', '/account/password');

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertStringEndsWith('/login', self::string($this->browser->getResponse()->headers->get('Location')));
    }

    /**
     * A guard the form does not repeat is a guard a form post goes around.
     */
    #[Test]
    public function aPasswordPostedOnASessionThatProvedNothingRecentlyIsNotWritten(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        $token = $this->token();
        self::mockTime(self::currentSecond()->add(new DateInterval(RecentLogin::WITHIN))->modify('+1 second'));

        // When
        $this->browser->request('POST', '/account/password', [
            '_token' => $token,
            'current_password' => self::IN_USE,
            'new_password' => self::POSED,
            'new_password_again' => self::POSED,
        ]);

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertTrue(self::hasher()->verify(self::passwordOf($alice)->hash, self::IN_USE));
    }

    /**
     * What the lane found after the password was posed is read here, where the person can do something
     * about it (issue #552).
     */
    #[Test]
    public function aPasswordFoundInABreachIsSaidOnThePage(): void
    {
        // Given
        $alice = self::userWithPassword('alice', self::IN_USE);
        $this->signIn($alice);
        $credential = self::passwordOf($alice);
        $credential->foundInABreach(self::currentSecond());
        self::service('test.beffroi.credentials', CredentialRepositoryInterface::class)->save($credential);

        // When
        $page = $this->passwordPage();

        // Then
        static::assertCount(1, $page->filter('p[data-password-breached]'));
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

    /**
     * The meter asks nobody anything: the page hands the script the words and the floor, and the script
     * reads the field it is pointed at. What is asserted here is what the page tells it; what it makes of
     * a password is the core's vectors (PasswordStrengthTest).
     */
    #[Test]
    public function thePageHandsTheMeterItsWordsAndItsFloor(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));

        // When
        $page = $this->passwordPage();

        // Then
        $field = $page->filter('input[data-password-strength]');
        static::assertCount(1, $field);
        static::assertSame('password-strength', $field->attr('data-password-strength'));
        static::assertSame((string) PlainPassword::MINIMUM_STRENGTH, $field->attr('data-strength-floor'));
        static::assertCount(5, (array) json_decode(self::string($field->attr('data-strength-labels')), true));
        static::assertCount(1, $page->filter('p#password-strength[data-strength-meter]'));
    }

    /**
     * Architecture §5.2: a script of the bundle, served by the bundle, cacheable, and nothing is loaded
     * from anywhere else.
     */
    #[Test]
    public function theScriptOfTheMeterIsServedByTheBundle(): void
    {
        // Given
        $this->signIn(self::userWithPassword('alice', self::IN_USE));
        static::assertSame('/password-strength.js', $this->passwordPage()->filter('script')->attr('src'));

        // When
        $this->browser->request('GET', '/password-strength.js');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertSame('text/javascript; charset=utf-8', $response->headers->get('Content-Type'));
        static::assertStringNotContainsString('fetch(', self::string($this->browser->getInternalResponse()->getContent()));
    }

    private function passwordPage(): Crawler
    {
        $page = $this->browser->request('GET', '/account/password');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());

        return $page;
    }

    private function change(string $inUse, string $posed, ?string $again = null): void
    {
        $this->browser->request('POST', '/account/password', [
            '_token' => $this->token(),
            'current_password' => $inUse,
            'new_password' => $posed,
            'new_password_again' => $again ?? $posed,
        ]);
    }

    /**
     * The list of this kernel, armed by the test that wants the rule.
     */
    private static function breaches(): BreachedPasswordsOfARecord
    {
        return self::service('test.beffroi.breached_passwords', BreachedPasswordsOfARecord::class);
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
