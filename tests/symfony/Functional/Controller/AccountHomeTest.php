<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * The home of the account (architecture §5.2): where a person who typed the issuer in a browser lands. It
 * names who is signed in, offers the pages of the account that are wired with what the account holds on
 * each, and sends a browser without a session to the login it comes back from.
 */
final class AccountHomeTest extends PasskeyTestCase
{
    private const string PASSWORD = 'correct horse battery staple';

    #[Test]
    public function aVisitorWithoutASessionSignsInAndLandsBackOnTheirAccount(): void
    {
        // Given
        self::userWithPassword('alice', self::PASSWORD);

        // When
        $this->browser->request('GET', '/account');

        // Then
        static::assertSame('/login', $this->browser->getResponse()->headers->get('Location'));
        $crawler = $this->browser->followRedirect();
        $this->browser->submit($crawler
            ->selectButton('Sign in')
            ->form([
                '_username' => 'alice',
                '_password' => self::PASSWORD,
            ]));
        static::assertSame('/account', $this->browser->getResponse()->headers->get('Location'));
        $crawler = $this->browser->followRedirect();
        static::assertStringContainsString('Signed in as alice.', $crawler->filter('main')->text());
    }

    #[Test]
    public function thePageNamesTheUserAndWhenTheySignedIn(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));

        // When
        $crawler = $this->accountPage();

        // Then
        self::assertInteractionHeaders($this->browser->getResponse());
        static::assertStringContainsString('Signed in as alice.', $crawler->filter('main')->text());
        static::assertSame(
            $session->establishedAt->format('c'),
            $crawler->filter('time')->attr('datetime'),
        );
    }

    #[Test]
    public function thePageOffersThePagesOfTheAccountThatAreWired(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->accountPage();

        // Then
        static::assertCount(8, $crawler->filter('ul[data-sections="8"] li'));
        // first of them: it is what makes the page of what somebody is waiting on findable (BCP 10027 §5.2)
        $approvals = $crawler->filter('li[data-section="beffroi_interaction_account_approvals"]');
        static::assertSame('/account/approvals', $approvals->filter('a')->attr('href'));
        static::assertSame('Requests waiting for you', $approvals->filter('a')->text());
        static::assertSame('Nothing waiting for you', $approvals->filter('span[data-state]')->text());
        $profile = $crawler->filter('li[data-section="beffroi_interaction_account_profile"]');
        static::assertSame('/account/profile', $profile->filter('a')->attr('href'));
        static::assertSame('Your information', $profile->filter('a')->text());
        static::assertSame('Nothing filled in', $profile->filter('span[data-state]')->text());
        $passkeys = $crawler->filter('li[data-section="beffroi_interaction_account_passkeys"]');
        static::assertSame('/account/passkeys', $passkeys->filter('a')->attr('href'));
        static::assertSame('Your passkeys', $passkeys->filter('a')->text());
        static::assertSame('No passkey', $passkeys->filter('span[data-state]')->text());
        $twoFactor = $crawler->filter('li[data-section="beffroi_interaction_account_two_factor"]');
        static::assertSame('/account/two-factor', $twoFactor->filter('a')->attr('href'));
        static::assertSame('No authenticator app', $twoFactor->filter('span[data-state]')->text());
        $consents = $crawler->filter('li[data-section="beffroi_interaction_account_consents"]');
        static::assertSame('/account/consents', $consents->filter('a')->attr('href'));
        static::assertSame('Applications you have allowed', $consents->filter('a')->text());
        static::assertSame('No application', $consents->filter('span[data-state]')->text());
        $sessions = $crawler->filter('li[data-section="beffroi_interaction_account_sessions"]');
        static::assertSame('/account/sessions', $sessions->filter('a')->attr('href'));
        static::assertSame('Where you are signed in', $sessions->filter('a')->text());
        static::assertSame('one session open', $sessions->filter('span[data-state]')->text());
        $notifications = $crawler->filter('li[data-section="beffroi_interaction_account_notifications"]');
        static::assertSame('/account/notifications', $notifications->filter('a')->attr('href'));
        static::assertSame('Notifications', $notifications->filter('a')->text());
        static::assertSame('No browser told', $notifications->filter('span[data-state]')->text());
    }

    #[Test]
    public function thePageCountsThePasskeysTheAccountHolds(): void
    {
        // Given
        $this->enrol(self::user('alice'), self::device());

        // When
        $crawler = $this->accountPage();

        // Then
        static::assertSame(
            'One passkey',
            $crawler->filter('li[data-section="beffroi_interaction_account_passkeys"] span[data-state]')->text(),
        );
    }

    #[Test]
    public function thePageOffersTheWayOut(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->accountPage();

        // Then
        $link = $crawler->filter('main a[href="/logout"]');
        static::assertCount(1, $link);
        static::assertSame('Sign out', $link->text());
    }

    private function accountPage(): Crawler
    {
        $crawler = $this->browser->request('GET', '/account');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }
}
