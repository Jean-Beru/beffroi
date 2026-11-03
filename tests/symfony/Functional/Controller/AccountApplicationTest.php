<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use Beffroi\Oidc\Port\RefreshTokensOfAConsentInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Issue #451, architecture §4.3, §5.2: what one application holds of a person, behind each line of what
 * they agreed to. What taking it back revokes is the consent and everything issued under it, in one act,
 * which is ConsentRevocation and is tested where it lives; this page asks for it and says what it means.
 */
final class AccountApplicationTest extends BrowserTestCase
{
    private const string CONFIDENTIAL = 'legacy-app';

    #[Test]
    public function thePageSaysWhatWasGrantedAndWhen(): void
    {
        // Given
        $this->allow(self::user('alice'));

        // When
        $page = $this->applicationPage();

        // Then
        static::assertSame(['openid', 'profile'], $page->filter('dl[data-application="granted"] li[data-scope]')->extract(['data-scope']));
        static::assertNotSame('', $page->filter('dl[data-application="granted"] time')->attr('datetime'));
    }

    #[Test]
    public function thePageCountsWhatTheApplicationCanStillRenew(): void
    {
        // Given
        $this->allowAndTakeTheTokens(self::user('alice'));

        // When
        $page = $this->applicationPage(self::CONFIDENTIAL);

        // Then
        static::assertSame('1', $page->filter('p[data-application="renewable"]')->attr('data-renewable'));
        static::assertCount(1, $page->filter('p[data-application="last-issued"]'));
    }

    #[Test]
    public function anApplicationWaitingForNothingSaysSo(): void
    {
        // Given
        $this->allow(self::user('alice'));

        // When
        $page = $this->applicationPage();

        // Then
        static::assertSame('0', $page->filter('[data-application="pending"]')->attr('data-pending'));
    }

    #[Test]
    public function takingItBackFromThePageStopsWhatItHeldFromRenewing(): void
    {
        // Given
        $alice = self::user('alice');
        $this->allowAndTakeTheTokens($alice);
        $consent = $this->consentOf($alice);

        // When
        $this->browser->submit($this->applicationPage(self::CONFIDENTIAL)->selectButton('Take it all back')->form());

        // Then
        static::assertSame(Response::HTTP_SEE_OTHER, $this->browser->getResponse()->getStatusCode());
        static::assertSame([], self::service('test.beffroi.active_consents', ActiveConsentsInterface::class)->activeOf($alice));
        $renewals = self::service('test.beffroi.refresh_tokens', RefreshTokensOfAConsentInterface::class)->ofConsent($consent);
        static::assertNotSame([], $renewals);
        foreach ($renewals as $token) {
            static::assertTrue($token->isRevoked());
        }
    }

    #[Test]
    public function anApplicationTheyAgreedToNothingForHasNoPage(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/account/applications/' . Uuid::v7()->toRfc4122());

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    private function applicationPage(string $clientId = 'native-app'): Crawler
    {
        $page = $this->browser->request('GET', '/account/consents');

        return $this->browser->click($page->filter('tr[data-client="' . $clientId . '"] a')->link());
    }

    private function allow(User $user, string $clientId = 'native-app', string $redirectUri = 'http://127.0.0.1/callback'): string
    {
        $this->signIn($user);
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, ['redirect_uri' => $redirectUri]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $crawler = $this->browser->request('GET', '/consent', ['interaction' => $interaction]);
        $this->browser->submit($crawler->selectButton('Allow')->form());

        return self::string(self::redirectedQuery($this->browser->getResponse())['code'] ?? null);
    }

    /**
     * A confidential client is issued something to renew with without asking for "offline_access", which
     * a public one has to ask for and this deployment offers to none of them (RefreshTokenDue).
     */
    private function allowAndTakeTheTokens(User $user): void
    {
        self::signingKey();
        $code = $this->allow($user, self::CONFIDENTIAL, 'https://legacy.test/callback');
        // this one names itself in the body (client_secret_post), which is its registered method
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'https://legacy.test/callback',
            'code_verifier' => self::CODE_VERIFIER,
            'client_id' => self::CONFIDENTIAL,
            'client_secret' => 'legacy-secret-of-at-least-32-characters-long',
        ]);
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode(), self::string($this->browser->getResponse()->getContent()));
    }

    private function consentOf(User $user): Consent
    {
        return (
            self::service('test.beffroi.active_consents', ActiveConsentsInterface::class)->activeOf($user)[0] ?? static::fail('The user has agreed to nothing.')
        );
    }
}
