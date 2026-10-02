<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Core\Domain\Identity\User;
use Beffroi\Oidc\Domain\Consent\Consent;
use Beffroi\Oidc\Port\ActiveConsentsInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * The page of what the signed-in user has agreed to (architecture §4.3, §5.2): the clients that may
 * obtain something about them, and what taking one back does to the client, from the page to the token
 * endpoint and to UserInfo.
 */
final class AccountConsentsTest extends BrowserTestCase
{
    private const string LEGACY_SECRET = 'legacy-secret-of-at-least-32-characters-long';

    private const string LEGACY_REDIRECT_URI = 'https://legacy.test/callback';

    #[Test]
    public function thePageNeedsASessionOfTheCore(): void
    {
        // When
        $crawler = $this->browser->request('GET', '/account/consents');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('login_required', $crawler->filter('p[data-error]')->attr('data-error'));
    }

    #[Test]
    public function thePageListsNothingForAUserWhoAllowedNobody(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->consentsPage();

        // Then
        self::assertInteractionHeaders($this->browser->getResponse());
        static::assertCount(1, $crawler->filter('p[data-consents="none"]'));
        static::assertCount(0, $crawler->filter('table'));
    }

    #[Test]
    public function thePageNamesTheClientTheScopesAndTheDate(): void
    {
        // Given
        $this->allow(self::user('alice'));

        // When
        $crawler = $this->consentsPage();

        // Then
        $row = $crawler->filter('table[data-consents="1"] tr[data-client="native-app"]');
        static::assertCount(1, $row);
        static::assertSame(['openid', 'profile'], $row->filter('li[data-scope]')->extract(['data-scope']));
        static::assertNotSame('', $row->filter('time')->attr('datetime'));
        static::assertSame(
            '/account/consents/' . $row->attr('data-consent') . '/revoke',
            $row->filter('form')->attr('action'),
        );
    }

    #[Test]
    public function takingAConsentBackLeavesTheListEmpty(): void
    {
        // Given
        $this->allow(self::user('alice'));
        $crawler = $this->consentsPage();

        // When
        $this->browser->submit($crawler->selectButton('Take back')->form());

        // Then
        static::assertSame('/account/consents', $this->browser->getResponse()->headers->get('Location'));
        static::assertCount(1, $this->browser->followRedirect()->filter('p[data-consents="none"]'));
    }

    /**
     * Architecture §4.3: a consent is what makes the provider ask once rather than at every request;
     * taking it back is how a user changes their mind.
     */
    #[Test]
    public function theClientAsksAfreshOnceItsConsentIsTakenBack(): void
    {
        // Given
        $this->allow(self::user('alice'));
        $this->takeBack();

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/consent?interaction=' . self::redirectedInteraction($response), $response->headers->get('Location'));
    }

    /**
     * Architecture §4.6: a resource of this provider asks whether the grant a token descends from is
     * still alive, and the consent taken back revoked it.
     */
    #[Test]
    public function theAccessTokenOfThatClientNoLongerOpensUserInfo(): void
    {
        // Given
        self::signingKey();
        $this->exchange($this->allow(self::user('alice')));
        $accessToken = self::string(self::json($this->browser->getResponse())['access_token']);
        $this->takeBack();

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode(), self::string($response->getContent()));
        static::assertStringContainsString('invalid_token', self::string($response->headers->get('WWW-Authenticate')));
    }

    /**
     * RFC 6749 §6: nothing renews, so what a confidential client holds runs out and is not replaced.
     */
    #[Test]
    public function theRefreshTokenOfThatClientIsRefused(): void
    {
        // Given
        self::signingKey();
        $refreshToken = self::string($this->tokensOfTheLegacyClient()['refresh_token']);
        $this->takeBack();

        // When
        $this->browser->request('POST', '/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => 'legacy-app',
            'client_secret' => self::LEGACY_SECRET,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('invalid_grant', self::json($response)['error']);
    }

    /**
     * A consent is named to the POST by an identifier of the user's own list, so somebody else's is not
     * takeable back, signed in or not.
     */
    #[Test]
    public function aConsentOfAnotherUserIsNotFound(): void
    {
        // Given
        $alice = self::user('alice');
        $this->allow($alice);
        $ofAlice = $this->consentOf($alice);
        // the same browser, signed in as somebody else, holding a form of their own list
        $this->allow(self::user('bob', 'bob-subject'));
        $token = self::string($this->consentsPage()->filter('input[name="_token"]')->attr('value'));

        // When
        $this->browser->request('POST', '/account/consents/' . $ofAlice->id->toRfc4122() . '/revoke', [
            '_token' => $token,
        ]);

        // Then
        static::assertSame(Response::HTTP_NOT_FOUND, $this->browser->getResponse()->getStatusCode());
        static::assertTrue($this->consentOf($alice)->isActive());
    }

    #[Test]
    public function theFormRefusesAForeignSubmission(): void
    {
        // Given
        $alice = self::user('alice');
        $this->allow($alice);
        $consent = $this->consentOf($alice);

        // When
        $this->browser->request('POST', '/account/consents/' . $consent->id->toRfc4122() . '/revoke', [
            '_token' => 'forged',
        ]);

        // Then
        static::assertSame(Response::HTTP_FORBIDDEN, $this->browser->getResponse()->getStatusCode());
        static::assertTrue($this->consentOf($alice)->isActive());
    }

    /**
     * The code the native client gets once the user signed in and allowed, which leaves a consent behind.
     *
     * @param array<string, string|null> $parameters what the authorization request carries beyond the defaults
     */
    private function allow(User $user, string $clientId = 'native-app', array $parameters = []): string
    {
        $this->signIn($user);
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, $parameters));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $this->browser->submit($crawler->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    private function takeBack(): void
    {
        $this->browser->submit($this->consentsPage()->selectButton('Take back')->form());
        static::assertSame(Response::HTTP_FOUND, $this->browser->getResponse()->getStatusCode());
    }

    private function exchange(string $code): void
    {
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'http://127.0.0.1/callback',
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);
    }

    /**
     * The tokens of a confidential client, which gets a refresh token without asking for
     * "offline_access" (RFC 6749 §4.1.4), and which registered the exception of decision 0008.
     *
     * @return array<string, mixed>
     */
    private function tokensOfTheLegacyClient(): array
    {
        $code = $this->allow(self::user('alice'), 'legacy-app', [
            'redirect_uri' => self::LEGACY_REDIRECT_URI,
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]);
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::LEGACY_REDIRECT_URI,
            'client_id' => 'legacy-app',
            'client_secret' => self::LEGACY_SECRET,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
    }

    private function consentsPage(): Crawler
    {
        $crawler = $this->browser->request('GET', '/account/consents');
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));

        return $crawler;
    }

    private function consentOf(User $user): Consent
    {
        return (
            self::service('test.beffroi.active_consents', ActiveConsentsInterface::class)->activeOf($user)[0] ?? static::fail('The user has agreed to nothing.')
        );
    }
}
