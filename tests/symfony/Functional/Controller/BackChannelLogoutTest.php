<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function array_map;
use App\Tests\Symfony\Functional\MessageHandler\RecordingEventHandler;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\EndSession\LogoutToken;
use Beffroi\Oidc\Domain\Event\LogoutTokenIssued;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Back-Channel Logout 1.0 §2.4, §2.6, Architecture §4.9
 */
final class BackChannelLogoutTest extends BrowserTestCase
{
    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function everyClientOfTheSessionThatRegisteredAUriGetsALogoutToken(): void
    {
        // Given
        $this->signedInWithFourClients();

        // When
        $this->logOut();

        // Then
        static::assertSame(['legacy-app', 'oidc-demo', 'opaque-app'], self::clientsTold());
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aClientThatSignedInTwiceIsToldOnce(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        self::signingKey();
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');

        // When
        $this->logOut();

        // Then
        static::assertSame(['oidc-demo'], self::clientsTold());
    }

    /**
     * Back-Channel Logout 1.0 §2.4
     */
    #[Test]
    public function theTokenNamesTheClientAndTheSessionThatEnded(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        self::signingKey();
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');

        // When
        $this->logOut();

        // Then
        [$issued] = self::logoutTokens();
        static::assertSame('oidc-demo', $issued->clientId);
        static::assertSame('https://demo.test/backchannel-logout', $issued->logoutUri->value);
        $claims = self::claimsOf($issued->token);
        static::assertSame('https://op.test', $claims['iss']);
        static::assertSame('oidc-demo', $claims['aud']);
        static::assertSame($session->id->toRfc4122(), $claims['sid']);
        static::assertSame('alice-subject', $claims['sub']);
        $events = $claims['events'];
        static::assertIsArray($events);
        static::assertArrayHasKey(LogoutToken::EVENT, $events);
        static::assertArrayNotHasKey('nonce', $claims);
    }

    /**
     * Back-Channel Logout 1.0 §2.6
     */
    #[Test]
    public function aLogoutTheUserRefusesTellsNobody(): void
    {
        // Given
        $this->signedInWithFourClients();
        $crawler = $this->confirmationPage();

        // When
        $this->browser->submit($crawler->selectButton('Stay signed in')->form());

        // Then
        static::assertSame([], self::clientsTold());
    }

    /**
     * RP-Initiated Logout §4
     */
    #[Test]
    public function aLogoutWithoutASessionTellsNobody(): void
    {
        // When
        $this->browser->request('GET', '/logout');

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame([], self::clientsTold());
    }

    private function signedInWithFourClients(): User
    {
        $user = self::user('alice');
        $this->signIn($user);
        self::signingKey();
        $this->signInClient('native-app', 'http://127.0.0.1/callback', null);
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');
        $this->signInClient('opaque-app', 'https://opaque.test/callback', 'opaque-secret-of-at-least-32-characters-long');
        $this->signInClient('legacy-app', 'https://legacy.test/callback', 'legacy-secret-of-at-least-32-characters-long');

        return $user;
    }

    /**
     * OIDC Core §8.1
     */
    #[Test]
    public function theTokenOfAPairwiseClientNamesTheUserUnderTheIdentifierThatClientSees(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        self::signingKey();
        $this->signInClient('pairwise-app', 'https://pairwise.test/callback', 'pairwise-secret-of-at-least-32-characters');
        $subject = self::claimsOf(self::string(self::json($this->browser->getResponse())['id_token']))['sub'];

        // When
        $this->logOut();

        // Then
        [$issued] = self::logoutTokens();
        static::assertSame('pairwise-app', $issued->clientId);
        static::assertSame($subject, self::claimsOf($issued->token)['sub']);
        static::assertNotSame('alice-subject', $subject);
    }

    private function logOut(): void
    {
        $this->browser->submit($this->confirmationPage()->selectButton('Sign out')->form());
    }

    private function confirmationPage(): Crawler
    {
        return $this->browser->request('GET', '/logout', [
            'client_id' => 'oidc-demo',
        ]);
    }

    /**
     * @return list<string> sorted
     */
    private static function clientsTold(): array
    {
        $told = array_map(static fn (LogoutTokenIssued $event): string => $event->clientId, self::logoutTokens());
        sort($told);

        return $told;
    }

    /**
     * @return list<LogoutTokenIssued>
     */
    private static function logoutTokens(): array
    {
        $issued = [];
        foreach (self::service(RecordingEventHandler::class, RecordingEventHandler::class)->events as $event) {
            if ($event instanceof LogoutTokenIssued) {
                $issued[] = $event;
            }
        }

        return $issued;
    }
}
