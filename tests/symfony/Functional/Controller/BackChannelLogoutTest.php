<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use function array_map;
use function base64_encode;
use Heidi\Bundle\Tests\Functional\MessageHandler\RecordingEventHandler;
use Heidi\Core\Domain\Identity\User;
use Heidi\Oidc\Domain\EndSession\LogoutToken;
use Heidi\Oidc\Domain\Event\LogoutTokenIssued;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use function sprintf;
use function str_starts_with;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Back-Channel Logout 1.0 §2.4 and §2.6, architecture §4.9: a session that ends through the end session
 * endpoint leaves one logout token per client it signed in that registered a URI, and none for the
 * others. What carries them to those URIs is not this test (architecture §5.6).
 */
final class BackChannelLogoutTest extends BrowserTestCase
{
    /**
     * §2.6: three clients of the session hold a token and declare a back-channel logout URI; the native
     * client declares none and is not told.
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
     * §2.6: one token per client, whatever the number of times that client signed in during the session.
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
     * §2.4: the token is addressed to its client, names the session that ended, and is the security event
     * token of the specification, not an ID token.
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
        static::assertSame('oidc-demo', $issued->client->clientId);
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
     * §2.6: a session the user refuses to end tells nobody; the announcement is made on the end, never on
     * the request that asks for one.
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
     * A browser that holds no session ends nothing, so there is nothing to announce (§4 of RP-Initiated
     * Logout: the request is idempotent).
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

    /**
     * The session of alice, signed in by the three clients that registered a back-channel logout URI and
     * by the native one, which registered none.
     */
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
     * The whole code flow of one client on the session the browser holds: the authorization request, the
     * consent when the client requires one, then the code exchanged for tokens. A client holds a token of
     * the session from there on (§2.6).
     */
    private function signInClient(string $clientId, string $redirectUri, ?string $secret): void
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => $redirectUri,
        ]));
        $location = self::string($this->browser->getResponse()->headers->get('Location'));
        if (str_starts_with($location, '/consent?')) {
            $interaction = self::redirectedInteraction($this->browser->getResponse());
            $this->browser->submit($this->browser->request('GET', '/consent', [
                'interaction' => $interaction,
            ])->selectButton('Allow')
                ->form());
        }
        $code = self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail(sprintf('The client "%s" got no code.', $clientId));
        $parameters = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => self::CODE_VERIFIER,
        ];
        // the three authentication methods of the test kernel: a public client names itself and nothing else
        $server = [];
        if ($secret === null) {
            $parameters['client_id'] = $clientId;
        } elseif ($clientId === 'legacy-app') {
            $parameters['client_id'] = $clientId;
            $parameters['client_secret'] = $secret;
        } else {
            $server = [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
            ];
        }
        $this->browser->request('POST', '/token', $parameters, server: $server);
        static::assertIsString(self::json($this->browser->getResponse())['access_token'] ?? null, self::string($this->browser->getResponse()->getContent()));
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
     * @return list<string> sorted, the order of the grants being the repository's business
     */
    private static function clientsTold(): array
    {
        $told = array_map(static fn (LogoutTokenIssued $event): string => $event->client->clientId, self::logoutTokens());
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
