<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Event\AuthenticationSessionEnded;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Session\SessionEnd;
use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #450, architecture §5.2: a person sees the sessions open in their name and ends one. What ending
 * one does to the relying parties is the end of a session of the core, said once
 * (AuthenticationSessionEnded), which is what the back-channel logout reads; the command that ends one
 * calls the same use case.
 */
final class AccountSessionsTest extends BrowserTestCase
{
    #[Test]
    public function thePageListsTheSessionsOpenInTheirName(): void
    {
        // Given
        $alice = self::user('alice');
        $current = $this->signIn($alice);
        self::session($alice, self::currentSecond()->modify('-1 hour'));

        // When
        $page = $this->sessionsPage();

        // Then
        static::assertSame('2', $page->filter('table[data-sessions]')->attr('data-sessions'));
        static::assertSame('yes', $page->filter('tr[data-session="' . $current->id . '"]')->attr('data-current'));
    }

    #[Test]
    public function endingAnotherSessionEndsItAndSaysSoOnce(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $other = self::session($alice, self::currentSecond()->modify('-1 hour'));
        $token = $this->token($other);

        // When
        $this->browser->request('POST', '/account/sessions/' . $other->id . '/revoke', ['_token' => $token]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_SEE_OTHER, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/account/sessions', $response->headers->get('Location'));
        static::assertTrue(self::reread($other)->hasEnded());
        static::assertSame(SessionEnd::User, self::reread($other)->endedBy);
        static::assertCount(1, self::events(AuthenticationSessionEnded::class));
    }

    #[Test]
    public function endingTheirOwnSessionSignsThemOut(): void
    {
        // Given
        $current = $this->signIn(self::user('alice'));
        $token = $this->token($current);

        // When
        $crawler = $this->browser->request('POST', '/account/sessions/' . $current->id . '/revoke', ['_token' => $token]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('yes', $crawler->filter('[data-logged-out]')->attr('data-logged-out'));
        static::assertTrue(self::reread($current)->hasEnded());
    }

    #[Test]
    public function aBrowserWhoseSessionItEndedIsAskedToSignInAgain(): void
    {
        // Given
        $current = $this->signIn(self::user('alice'));
        $token = $this->token($current);
        $this->browser->request('POST', '/account/sessions/' . $current->id . '/revoke', ['_token' => $token]);

        // When
        $crawler = $this->browser->request('GET', '/account/sessions');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
        static::assertSame('login_required', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function theSessionOfSomebodyElseIsNotFound(): void
    {
        // Given
        $current = $this->signIn(self::user('alice'));
        $token = $this->token($current);
        $theirs = self::session(self::user('bob', 'bob-subject'));

        // When
        $this->browser->request('POST', '/account/sessions/' . $theirs->id . '/revoke', ['_token' => $token]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::reread($theirs)->hasEnded());
    }

    #[Test]
    public function aSessionEndedWithoutTheTokenOfItsFormIsRefused(): void
    {
        // Given
        $alice = self::user('alice');
        $this->signIn($alice);
        $other = self::session($alice, self::currentSecond()->modify('-1 hour'));

        // When
        $this->browser->request('POST', '/account/sessions/' . $other->id . '/revoke');

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertFalse(self::reread($other)->hasEnded());
        static::assertSame([], self::events(AuthenticationSessionEnded::class));
    }

    private function sessionsPage(): Crawler
    {
        return $this->browser->request('GET', '/account/sessions');
    }

    private function token(AuthenticationSession $session): string
    {
        return self::string(
            $this->sessionsPage()
                ->filter('tr[data-session="' . $session->id . '"] input[name="_token"]')
                ->attr('value'),
        );
    }

    private static function reread(AuthenticationSession $session): AuthenticationSession
    {
        $reread = self::service('test.beffroi.sessions', AuthenticationSessionRepositoryInterface::class)->find($session->id);
        static::assertInstanceOf(AuthenticationSession::class, $reread);

        return $reread;
    }
}
