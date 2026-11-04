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

final class TheOrderOfAPasswordLoginTest extends BrowserTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        self::userWithPassword(TheOrderOfAPasswordLogin::USERNAME, TheOrderOfAPasswordLogin::PASSWORD);
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

    #[Test]
    public function aFormWithoutAPasswordIsNoAttemptOnAnAccount(): void
    {
        // When
        $this->signInOnTheForm(TheOrderOfAPasswordLogin::USERNAME, '');

        // Then
        static::assertSame([], self::events(AuthenticationFailed::class));
    }

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
