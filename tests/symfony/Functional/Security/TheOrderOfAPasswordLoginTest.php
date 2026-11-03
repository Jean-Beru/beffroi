<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Security;

use App\Tests\Symfony\Functional\Controller\BrowserTestCase;
use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\PasswordUsed;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Port\UserRepositoryInterface;
use Beffroi\Core\Tests\Fixture\TheOrderOfAPasswordLogin;
use PHPUnit\Framework\Attributes\DataProviderExternal;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #130: the order of a login by password, played by the firewall. The use case of the core asks the
 * same of itself (TheOrderOfAPasswordLoginTest of the core suite), and the two read the same named steps
 * (TheOrderOfAPasswordLogin): this path hands the request to the verification of the core rather than
 * verifying a hash of its own, so a step added to one path is a case the other answers differently.
 *
 * What this path can be asked is what was announced, which is what a tenant reads of its audit trail: the
 * hash a refusal pays is what the core suite asks of the same steps.
 */
final class TheOrderOfAPasswordLoginTest extends BrowserTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::userWithPassword(TheOrderOfAPasswordLogin::USERNAME, TheOrderOfAPasswordLogin::PASSWORD);
        // a person of the same tenant who holds no password at all
        self::user(TheOrderOfAPasswordLogin::WITHOUT_A_PASSWORD, 'bob-subject');
        $disabled = self::userWithPassword(TheOrderOfAPasswordLogin::DISABLED, TheOrderOfAPasswordLogin::PASSWORD);
        $disabled->disable(self::currentSecond());
        self::service('test.beffroi.users', UserRepositoryInterface::class)->save($disabled);
        self::reload();
    }

    #[Test]
    #[DataProviderExternal(TheOrderOfAPasswordLogin::class, 'steps')]
    public function aLoginAnswersEachStepOfTheOrderAsTheOrderSaysItDoes(
        string $username,
        string $password,
        ?AuthenticationFailureReason $reason,
    ): void {
        // When
        $this->signInOnTheForm($username, $password);

        // Then
        static::assertSame($reason, self::events(AuthenticationFailed::class)[0]->reason ?? null);
    }

    /**
     * The last step of the order, read on its own because what it leaves behind is a session and not a
     * refusal: the password is announced as the act it is, the session as the outcome, and the browser is
     * bound to it.
     */
    #[Test]
    public function theRightPasswordOpensASessionAndSaysWhatProvedIt(): void
    {
        // When
        $this->signInOnTheForm(TheOrderOfAPasswordLogin::USERNAME, TheOrderOfAPasswordLogin::PASSWORD);

        // Then
        static::assertCount(1, self::events(PasswordUsed::class));
        static::assertCount(1, self::events(UserAuthenticated::class));
        static::assertSame([], self::events(AuthenticationFailed::class));
    }

    /**
     * A form that carries no password is no attempt at one: nothing is counted, nothing is announced, and
     * the page says what it says of every refusal.
     */
    #[Test]
    public function aFormWithoutAPasswordIsNoAttemptOnAnAccount(): void
    {
        // When
        $this->signInOnTheForm(TheOrderOfAPasswordLogin::USERNAME, '');

        // Then
        static::assertSame([], self::events(AuthenticationFailed::class));
    }

    /**
     * The one step the firewall adds to the order, and the reason it is first: a form posted without the
     * token of the page is not an attempt on the account it names, so it costs that person no attempt, no
     * hash and no act in their journal.
     */
    #[Test]
    public function aFormWithoutItsTokenIsNoAttemptOnAnAccountEither(): void
    {
        // When
        $this->browser->request('POST', '/login', [
            '_username' => TheOrderOfAPasswordLogin::USERNAME,
            '_password' => TheOrderOfAPasswordLogin::PASSWORD,
            '_csrf_token' => 'not the token of the page',
        ]);

        // Then
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertSame([], self::events(AuthenticationFailed::class));
        static::assertSame([], self::events(UserAuthenticated::class));
    }

    /**
     * The form of the login page, filled and posted as a person does, where the page the browser was
     * going to is its own account (LoginTarget).
     */
    private function signInOnTheForm(string $username, string $password): void
    {
        $this->browser->request('GET', '/account');
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
        $form = $this->browser->followRedirect()->selectButton('Sign in')->form();
        $form['_username'] = $username;
        $form['_password'] = $password;
        $this->browser->submit($form);
    }
}
