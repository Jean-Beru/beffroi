<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use function base64_encode;
use Closure;
use function hash;
use App\Tests\Symfony\Functional\Messenger\LogoutEndpoints;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Port\PasswordHasherInterface;
use Beffroi\Oidc\Domain\Client\ClientRecord;
use Beffroi\Oidc\Domain\Client\HashedClientSecret;
use Beffroi\Oidc\Domain\EndSession\FrontChannelLogoutPage;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\ClientStoreInterface;
use Beffroi\Oidc\Tests\Fixture\Secrets;
use PHPUnit\Framework\Attributes\Test;
use function sort;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Front-Channel Logout 1.0 §2, §3, Architecture §4.9, §5.2
 */
final class FrontChannelLogoutTest extends BrowserTestCase
{
    private const string STALE = 'stale-app';

    private const string STALE_REDIRECT_URI = 'https://stale.test/callback';

    private const string STALE_SECRET = 'stale-secret-of-at-least-32-characters-long';

    private LogoutEndpoints $endpoints;

    protected function setUp(): void
    {
        $this->endpoints = new LogoutEndpoints([LogoutEndpoints::answering(200)]);
        parent::setUp();
    }

    protected function configureContainer(): Closure
    {
        return $this->endpoints->takeOver(...);
    }

    /**
     * Front-Channel Logout 1.0 §2
     */
    #[Test]
    public function oneFrameIsLoadedForEachClientThatRegisteredAUri(): void
    {
        // Given
        $session = $this->signedInWithFourClients();

        // When
        $crawler = $this->logOut();

        // Then
        static::assertSame(
            [
                'https://legacy.test/frontchannel-logout?app=1',
                'https://opaque.test/frontchannel-logout?iss=https%3A%2F%2Fop.test&sid=' . $session->id->toRfc4122(),
            ],
            self::framesOf($crawler),
        );
    }

    /**
     * Front-Channel Logout 1.0 §2
     */
    #[Test]
    public function theSessionIsNamedOnlyToTheClientThatAskedForIt(): void
    {
        // Given
        $session = $this->signedInWithFourClients();

        // When
        $frames = self::framesOf($this->logOut());

        // Then
        static::assertSame('https://legacy.test/frontchannel-logout?app=1', $frames[0]);
        static::assertSame(
            'https://opaque.test/frontchannel-logout?iss=https%3A%2F%2Fop.test&sid=' . $session->id->toRfc4122(),
            $frames[1],
        );
        static::assertStringNotContainsString('sid=', $frames[0]);
    }

    /**
     * Front-Channel Logout 1.0 §2
     */
    #[Test]
    public function thePageAllowsItsFramesItsScriptAndNothingElse(): void
    {
        // Given
        $this->signedInWithFourClients();

        // When
        $this->logOut();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        static::assertStringContainsString('no-store', self::string($response->headers->get('Cache-Control')));
        static::assertSame(
            "default-src 'none'; frame-src https://legacy.test https://opaque.test; script-src '"
            . self::scriptHash()
            . "'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
            $response->headers->get('Content-Security-Policy'),
        );
    }

    /**
     * RP-Initiated Logout §3
     */
    #[Test]
    public function thePageCarriesTheBrowserBackToTheClientThatAsked(): void
    {
        // Given
        $this->signedInWithFourClients();

        // When
        $crawler = $this->logOut();

        // Then
        static::assertSame('https://demo.test/?state=after-logout', $crawler->filter('main a')->attr('href'));
        static::assertStringContainsString(
            'content="' . FrontChannelLogoutPage::WAIT . ';url=https://demo.test/?state=after-logout"',
            self::string($this->browser->getResponse()->getContent()),
        );
    }

    #[Test]
    public function aLogoutWithNowhereToGoBackToEndsOnThePage(): void
    {
        // Given
        $this->signedInWithFourClients();

        // When
        $crawler = $this->logOut(postLogoutRedirectUri: null);

        // Then
        static::assertCount(2, self::framesOf($crawler));
        static::assertCount(0, $crawler->filter('main a'));
        static::assertStringContainsString("script-src 'none'", self::string($this->browser->getResponse()->headers->get('Content-Security-Policy')));
    }

    #[Test]
    public function aSessionWithNoSuchClientIsSentBackWithoutAPage(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        self::signingKey();
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');

        // When
        $this->logOut();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('https://demo.test/?state=after-logout', $response->headers->get('Location'));
    }

    /**
     * RFC 7591 §2, Architecture §4.1
     */
    #[Test]
    public function aClientWhoseRowNoLongerReadsLeavesThePageOfTheSessionToTheOthers(): void
    {
        // Given
        self::registerTheStaleClient();
        $session = $this->signedInWithFourClients();
        $this->signInClient(self::STALE, self::STALE_REDIRECT_URI, self::STALE_SECRET);
        self::rewriteTheRowOfTheStaleClient('https://stale.test;sandbox/frontchannel-logout');

        // When
        $crawler = $this->logOut();

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame(
            [
                'https://legacy.test/frontchannel-logout?app=1',
                'https://opaque.test/frontchannel-logout?iss=https%3A%2F%2Fop.test&sid=' . $session->id->toRfc4122(),
            ],
            self::framesOf($crawler),
        );
        static::assertStringStartsWith(
            "default-src 'none'; frame-src https://legacy.test https://opaque.test; script-src",
            self::string($response->headers->get('Content-Security-Policy')),
        );
    }

    /**
     * Back-Channel Logout 1.0 §3, Front-Channel Logout 1.0 §3
     */
    #[Test]
    public function theDiscoveryDocumentAnnouncesBothChannels(): void
    {
        // When
        $this->browser->request('GET', '/.well-known/openid-configuration');

        // Then
        $document = self::json($this->browser->getResponse());
        static::assertTrue($document['backchannel_logout_supported']);
        static::assertTrue($document['backchannel_logout_session_supported']);
        static::assertTrue($document['frontchannel_logout_supported']);
        static::assertTrue($document['frontchannel_logout_session_supported']);
    }

    private function signedInWithFourClients(): AuthenticationSession
    {
        $session = $this->signIn(self::user('alice'));
        self::signingKey();
        $this->signInClient('legacy-app', 'https://legacy.test/callback', 'legacy-secret-of-at-least-32-characters-long');
        $this->signInClient('opaque-app', 'https://opaque.test/callback', 'opaque-secret-of-at-least-32-characters-long');
        $this->signInClient('native-app', 'http://127.0.0.1/callback', null);
        $this->signInClient('oidc-demo', 'https://demo.test/login/check', 'demo-secret-of-at-least-32-characters-long');

        return $session;
    }

    /**
     * RFC 7591 §3.1
     */
    private static function registerTheStaleClient(): void
    {
        self::service('test.beffroi.client_store', ClientStoreInterface::class)
            ->save(new ClientRecord(
                Uuid::v7(),
                self::tenant(),
                self::STALE,
                self::staleMembers('https://stale.test/frontchannel-logout'),
                [],
                new HashedClientSecret(self::service('test.beffroi.password_hasher', PasswordHasherInterface::class)->hash(self::STALE_SECRET)),
                DrawnSecret::digestOf(Secrets::draw()),
                self::now(),
            ));
        self::reload();
    }

    private static function rewriteTheRowOfTheStaleClient(string $frontChannelLogoutUri): void
    {
        $store = self::service('test.beffroi.client_store', ClientStoreInterface::class);
        $record = $store->findRecord(self::tenant(), self::STALE) ?? static::fail('The stale client has no row.');
        $record->replaceWith(self::staleMembers($frontChannelLogoutUri), $record->assigned, $record->secret);
        $store->save($record);
        self::reload();
    }

    /**
     * @return array<string, mixed>
     */
    private static function staleMembers(string $frontChannelLogoutUri): array
    {
        return [
            'client_name' => 'A client that registered itself before the rule',
            'redirect_uris' => [self::STALE_REDIRECT_URI],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'scope' => 'openid profile',
            'frontchannel_logout_uri' => $frontChannelLogoutUri,
        ];
    }

    private function logOut(?string $postLogoutRedirectUri = 'https://demo.test/'): Crawler
    {
        $parameters = [
            'client_id' => 'oidc-demo',
        ];
        if ($postLogoutRedirectUri !== null) {
            $parameters['post_logout_redirect_uri'] = $postLogoutRedirectUri;
            $parameters['state'] = 'after-logout';
        }

        return $this->browser->submit($this->browser->request('GET', '/logout', $parameters)->selectButton('Sign out')->form());
    }

    /**
     * @return list<string> sorted
     */
    private static function framesOf(Crawler $crawler): array
    {
        $frames = $crawler->filter('iframe')->each(static fn (Crawler $frame): string => self::string($frame->attr('src')));
        sort($frames);

        return $frames;
    }

    /**
     * Computed here (CSP Level 3 §6.6.2.2) rather than asked of the module, so that the page and the policy are not
     * checked against each other.
     */
    private static function scriptHash(): string
    {
        return 'sha256-' . base64_encode(hash('sha256', FrontChannelLogoutPage::SCRIPT, true));
    }
}
