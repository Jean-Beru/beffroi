<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Session\SessionFactoryInterface;

/**
 * beffroi/saml S-28, "The plane"
 */
final class CrossSiteSessionCookieTest extends BrowserTestCase
{
    private const string BODY = '_token=forged&SAMLResponse=PHNhbWw%2B&confirm=yes&field=value';

    protected function setUp(): void
    {
        parent::setUp();
        $this->signIn(self::user('alice'));
    }

    /**
     * S-28, "The plane"
     */
    #[Test]
    #[DataProvider('provideEndpointsOfTheInteractionPlane')]
    public function aPostFromAnotherSiteIsAnsweredWithoutASessionCookie(string $path): void
    {
        // When
        $this->postedFromAnotherSite($path, self::BODY);

        // Then
        static::assertNotContains($this->sessionName(), $this->cookiesSet());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideEndpointsOfTheInteractionPlane(): iterable
    {
        yield 'the approvals of the account' => ['/account/approvals'];
        yield 'the archive of the account' => ['/account/archive'];
        yield 'the password of the account' => ['/account/password'];
        yield 'the other sessions of the account' => ['/account/sessions/revoke-others'];
        yield 'the consent' => ['/consent'];
        yield 'the verification of a device' => ['/device'];
        yield 'the choice of a language' => ['/locale'];
        yield 'the login' => ['/login'];
        yield 'the login by a code' => ['/login/code'];
        yield 'the login by a passkey' => ['/login/passkey'];
        yield 'the single sign-on service' => ['/saml/sso'];
        yield 'the single logout service' => ['/saml/slo'];
        yield 'the authorization endpoint' => ['/authorize'];
        yield 'the end session endpoint' => ['/logout'];
    }

    /**
     * S-28, "The plane"
     */
    #[Test]
    public function aPostFromTheSameOriginWithoutASessionIsGivenOne(): void
    {
        // When
        $this->postedFromAnotherSite('/login', self::BODY, ['HTTP_SEC_FETCH_SITE' => 'same-origin']);

        // Then
        static::assertContains($this->sessionName(), $this->cookiesSet());
    }

    /**
     * S-28, "The plane"
     */
    #[Test]
    public function aGetFromAnotherSiteWithoutASessionIsGivenOne(): void
    {
        // Given
        $this->browser->getCookieJar()->clear();

        // When
        $this->browser->request(
            'GET',
            '/authorize',
            self::authorizationParameters('oidc-demo'),
            [],
            [
                'HTTP_SEC_FETCH_SITE' => 'cross-site',
            ],
        );

        // Then
        static::assertContains($this->sessionName(), $this->cookiesSet());
    }

    private function sessionName(): string
    {
        return self::service('session.factory', SessionFactoryInterface::class)->createSession()->getName();
    }

    /**
     * @return list<string>
     */
    private function cookiesSet(): array
    {
        $names = [];
        foreach ($this->browser->getResponse()->headers->getCookies() as $cookie) {
            $names[] = $cookie->getName();
        }

        return $names;
    }
}
