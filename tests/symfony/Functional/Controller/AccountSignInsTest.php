<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Event\AuthenticationFailed;
use Beffroi\Core\Domain\Event\AuthenticationFailureReason;
use Beffroi\Core\Domain\Event\DomainEventInterface;
use Beffroi\Core\Domain\Event\UserAuthenticated;
use Beffroi\Core\Domain\Identity\User;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Messenger\MessageBusInterface;

/**
 * Issue #454, architecture §5.2: what the journal holds of the sign-ins of one person, on the page of
 * their account. The refusals are on it as well as the successes, because a line somebody does not
 * recognise is what the page is for.
 */
final class AccountSignInsTest extends BrowserTestCase
{
    #[Test]
    public function thePageShowsASignInThatSucceeded(): void
    {
        // Given
        $alice = self::user('alice');
        $session = self::session($alice, self::currentSecond());
        self::announce(new UserAuthenticated($session));
        $this->signIn($alice);

        // When
        $page = $this->signInsPage();

        // Then
        static::assertSame('1', $page->filter('table[data-sign-ins]')->attr('data-sign-ins'));
        static::assertSame(['succeeded'], $page->filter('tbody tr')->extract(['data-outcome']));
    }

    #[Test]
    public function thePageShowsAnAttemptThatWasRefused(): void
    {
        // Given
        $alice = self::user('alice');
        self::announce(self::refusedFor($alice));
        $this->signIn($alice);

        // When
        $page = $this->signInsPage();

        // Then
        static::assertSame(['failed'], $page->filter('tbody tr')->extract(['data-outcome']));
        static::assertSame([AuthenticationFailed::NAME], $page->filter('tbody tr')->extract(['data-act']));
    }

    /**
     * An act of somebody else is not on the page of this person: the journal is read by the subject of the
     * session the browser holds and never by anything the request carries.
     */
    #[Test]
    public function theActsOfSomebodyElseAreNotOnIt(): void
    {
        // Given
        $alice = self::user('alice');
        $bob = self::user('bob', 'bob-subject');
        self::announce(new UserAuthenticated(self::session($bob, self::currentSecond())));
        $this->signIn($alice);

        // When
        $page = $this->signInsPage();

        // Then
        static::assertCount(1, $page->filter('p[data-sign-ins="none"]'));
    }

    #[Test]
    public function aPersonWithNothingRecordedIsToldSo(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $page = $this->signInsPage();

        // Then
        static::assertCount(1, $page->filter('p[data-sign-ins="none"]'));
    }

    #[Test]
    public function aBrowserWithNoSessionIsRefused(): void
    {
        // When
        $this->browser->request('GET', '/account/sign-ins');

        // Then
        static::assertSame(Response::HTTP_UNAUTHORIZED, $this->browser->getResponse()->getStatusCode());
    }

    private function signInsPage(): Crawler
    {
        $page = $this->browser->request('GET', '/account/sign-ins');
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));

        return $page;
    }

    private static function refusedFor(User $user): AuthenticationFailed
    {
        return new AuthenticationFailed(
            self::currentSecond(),
            $user->tenant,
            self::context(),
            null,
            AuthenticationFailureReason::InvalidCredential,
            $user->username,
            $user,
        );
    }

    private static function announce(DomainEventInterface $event): void
    {
        self::service('event.bus', MessageBusInterface::class)->dispatch($event);
        self::reload();
    }
}
