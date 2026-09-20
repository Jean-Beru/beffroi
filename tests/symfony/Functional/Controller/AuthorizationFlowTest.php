<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use DateTimeImmutable;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §4.3 and §5.2, the acceptance criterion of the controllers: from /authorize to /userinfo
 * through the login and the consent pages, on the test kernel, with the module behind Doctrine. The
 * login itself is the one the firewall will do (#15): here the browser is handed a session the way the
 * firewall will hand it one. The code flow of a public client that requires consent, one step per test
 * (OIDC Core §3.1.2 to §3.1.3 and §5.3, RFC 7636, RFC 9207).
 */
final class AuthorizationFlowTest extends BrowserTestCase
{
    /**
     * Step 1: the authorization request parks an interaction and sends the browser to the login page.
     */
    #[Test]
    public function theAuthorizationRequestSendsTheBrowserToTheLoginPage(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertSame('/login?interaction=' . self::redirectedInteraction($response), $response->headers->get('Location'));
    }

    /**
     * Step 2: the login page shows the form of the firewall, with its CSRF token.
     */
    #[Test]
    public function theLoginPageShowsTheFormOfTheFirewall(): void
    {
        // Given
        $interaction = $this->beginAuthorization();

        // When
        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertCount(1, $crawler->filter('input[name="_username"]'));
        static::assertCount(1, $crawler->filter('input[name="_password"]'));
        static::assertNotSame('', $crawler->filter('input[name="_csrf_token"]')->attr('value'));
        static::assertSame('/login?interaction=' . $interaction, $crawler->filter('form')->attr('action'));
    }

    /**
     * Step 3: once the browser holds a session, the login page resumes the interaction: consent is required.
     */
    #[Test]
    public function theLoginPageResumesTheInteractionOnceTheBrowserHoldsASession(): void
    {
        // Given
        $interaction = $this->beginAuthorization();
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * Step 4: the consent page names the client, the user and every scope of the request.
     */
    #[Test]
    public function theConsentPageNamesTheUserAndTheScopes(): void
    {
        // Given
        $interaction = $this->beginAuthorization();
        $this->signIn(self::user('alice'));

        // When
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertStringContainsString('alice', self::string($response->getContent()));
        static::assertSame(['openid', 'profile'], $crawler->filter('li[data-scope]')->extract(['data-scope']));
        static::assertSame($interaction, $crawler->filter('input[name="interaction"]')->attr('value'));
    }

    /**
     * Step 5: the user allows, the code goes back to the client with "state" and "iss" (RFC 9207 §2).
     */
    #[Test]
    public function allowingSendsTheCodeBackToTheClientWithStateAndIssuer(): void
    {
        // Given
        $interaction = $this->beginAuthorization();
        $this->signIn(self::user('alice'));
        $crawler = $this->consentPage($interaction);

        // When
        $this->browser->submit($crawler->selectButton('Allow')->form());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertStringStartsWith('http://127.0.0.1/callback?code=', self::string($response->headers->get('Location')));
        $query = self::redirectedQuery($response);
        static::assertSame('state-of-the-client', $query['state']);
        static::assertSame('https://op.test', $query['iss']);
    }

    /**
     * Step 6: the code is exchanged (RFC 6749 §4.1.3, RFC 7636 §4.5).
     */
    #[Test]
    public function theCodeIsExchangedForTokens(): void
    {
        // Given
        self::signingKey();
        $code = $this->codeAllowedByAlice();

        // When
        $this->exchange($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        $tokens = self::json($response);
        static::assertSame('Bearer', $tokens['token_type']);
        static::assertSame('openid profile', $tokens['scope']);
        static::assertIsString($tokens['id_token']);
        static::assertIsString($tokens['access_token']);
    }

    /**
     * RFC 6749 §5.1: the token response is never cached.
     */
    #[Test]
    public function theTokenResponseIsNotCached(): void
    {
        // Given
        self::signingKey();
        $code = $this->codeAllowedByAlice();

        // When
        $this->exchange($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('no-cache', $response->headers->get('Pragma'));
    }

    /**
     * Architecture §4.5: a public client without offline_access gets no refresh token.
     */
    #[Test]
    public function aPublicClientWithoutOfflineAccessGetsNoRefreshToken(): void
    {
        // Given
        self::signingKey();
        $code = $this->codeAllowedByAlice();

        // When
        $this->exchange($code);

        // Then
        static::assertArrayNotHasKey('refresh_token', self::json($this->browser->getResponse()));
    }

    /**
     * Step 7: the access token opens UserInfo (OIDC Core §5.3).
     */
    #[Test]
    public function theAccessTokenOpensUserInfo(): void
    {
        // Given
        self::signingKey();
        $this->exchange($this->codeAllowedByAlice());
        $accessToken = self::string(self::json($this->browser->getResponse())['access_token']);

        // When
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('alice-subject', self::json($response)['sub']);
    }

    /**
     * Step 8: a second presentation of the code is a replay (RFC 6749 §4.1.2).
     */
    #[Test]
    public function aSecondPresentationOfTheCodeIsRefused(): void
    {
        // Given
        self::signingKey();
        $code = $this->codeAllowedByAlice();
        $this->exchange($code);

        // When
        $this->exchange($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_grant', self::json($response)['error']);
    }

    /**
     * RFC 6749 §4.1.2: the replay revokes what was issued from the code, so the access token handed out
     * on the first exchange no longer opens UserInfo. This is what the Basic OP profile checks after a
     * code reuse (oidcc-codereuse-30seconds).
     */
    #[Test]
    public function theAccessTokenOfAReplayedCodeNoLongerOpensUserInfo(): void
    {
        // Given
        self::signingKey();
        $code = $this->codeAllowedByAlice();
        $this->exchange($code);
        $accessToken = self::string(self::json($this->browser->getResponse())['access_token']);
        $this->exchange($code);

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
     * Step 9: the interaction is over, its pages are not reached again.
     */
    #[Test]
    public function theInteractionIsOverOnceTheCodeWasIssued(): void
    {
        // Given
        $interaction = $this->beginAuthorization();
        $this->signIn(self::user('alice'));
        $this->browser->submit($this->consentPage($interaction)->selectButton('Allow')->form());

        // When
        $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
        static::assertStringContainsString(AuthorizationResponder::UNKNOWN_INTERACTION, self::string($this->browser->getResponse()->getContent()));
    }

    /**
     * Architecture §4.3: a client that does not require consent, with a browser already signed in, gets
     * its code from the authorization endpoint directly; the request may be a POST (OIDC Core §3.1.2.1).
     */
    #[Test]
    public function aSignedInBrowserAndAFirstPartyClientGetTheCodeAtOnce(): void
    {
        // Given
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('POST', '/authorize', self::authorizationParameters('oidc-demo'));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('https://demo.test/login/check?code=', self::string($response->headers->get('Location')));
        static::assertSame('https://op.test', self::redirectedQuery($response)['iss']);
    }

    /**
     * RFC 6749 §4.1.2.1: the user denied, the client hears access_denied with its state and "iss".
     */
    #[Test]
    public function aDenialGoesBackToTheClient(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $crawler = $this->consentPage($this->beginAuthorization());

        // When
        $this->browser->submit($crawler->selectButton('Deny')->form());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame([
            'error' => 'access_denied',
            'error_description' => 'The end user denied the request.',
            'state' => 'state-of-the-client',
            'iss' => 'https://op.test',
        ], self::redirectedQuery($response));
    }

    /**
     * RFC 9700 §4.1, RFC 6749 §4.1.2.1: an error found before the redirect URI is validated is shown to
     * the user, never sent anywhere.
     */
    #[Test]
    public function anUnknownClientIsShownToTheUser(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('unknown-client'));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
        self::assertInteractionHeaders($response);
        static::assertStringContainsString('data-error="invalid_request"', self::string($response->getContent()));
    }

    /**
     * RFC 7636 §4.4.1, RFC 9207 §2: an error found once the client is known goes back to it with "iss".
     */
    #[Test]
    public function aMissingCodeChallengeGoesBackToTheClient(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('http://127.0.0.1/callback?', self::string($response->headers->get('Location')));
        $query = self::redirectedQuery($response);
        static::assertSame('invalid_request', $query['error']);
        static::assertSame('state-of-the-client', $query['state']);
        static::assertSame('https://op.test', $query['iss']);
    }

    /**
     * OIDC Core §3.1.2.6: prompt=none with no session is login_required, redirected.
     */
    #[Test]
    public function promptNoneWithoutASessionIsLoginRequired(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'prompt' => 'none',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('login_required', self::redirectedQuery($response)['error']);
    }

    /**
     * OIDC Core §5.5.1.1 and OIDC Core Error Code unmet_authentication_requirements §1: an essential "acr"
     * naming classes the provider cannot assert, here a name the policy of the tenant does not declare
     * (decision 0010), is refused to the client, with the state and the issuer, before any login page.
     */
    #[Test]
    public function anEssentialAcrTheProviderCannotAssertIsRefusedToTheClient(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'claims' => '{"id_token": {"acr": {"essential": true, "values": ["urn:mace:incommon:iap:silver"]}}}',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $query = self::redirectedQuery($response);
        static::assertSame('unmet_authentication_requirements', $query['error']);
        static::assertSame('state-of-the-client', $query['state']);
        static::assertSame('https://op.test', $query['iss']);
    }

    /**
     * Architecture §4.3: an interaction is resumed only by the browser that began it. Another browser
     * holding the identifier is told nothing but that no request waits for it.
     */
    #[Test]
    public function anotherBrowserCannotResumeAnInteraction(): void
    {
        // Given
        $interaction = $this->beginAuthorization();
        $other = self::browser();

        // When
        $other->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        $response = $other->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="' . AuthorizationResponder::UNKNOWN_INTERACTION . '"', self::string($response->getContent()));
    }

    /**
     * A login page reached without an interaction, or with one that does not exist.
     *
     * @param array<string, string> $parameters
     */
    #[Test]
    #[DataProvider('provideLoginPagesWithoutAnInteraction')]
    public function theLoginPageNeedsAnInteraction(array $parameters): void
    {
        // When
        $this->browser->request('GET', '/login', $parameters);

        // Then
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * @return iterable<string, array{array<string, string>}>
     */
    public static function provideLoginPagesWithoutAnInteraction(): iterable
    {
        yield 'no interaction' => [[]];
        yield 'an interaction that does not exist' => [[
            'interaction' => 'does-not-exist',
        ]];
    }

    /**
     * Architecture §4.3: an interaction lives ten minutes; after that the user starts again from the
     * client, nothing is sent to the redirect URI.
     */
    #[Test]
    public function anExpiredInteractionIsShownToTheUser(): void
    {
        // Given
        $interaction = $this->beginInteraction(new DateTimeImmutable('-20 minutes'), new DateTimeImmutable('-10 minutes'));

        // When
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction->id,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
        static::assertStringContainsString('data-error="' . AuthorizationResponder::INTERACTION_EXPIRED . '"', self::string($response->getContent()));
    }

    /**
     * OIDC Core §3.1.2.1 prompt=login: a session older than the interaction does not satisfy the
     * request, the login page is shown to the signed-in user rather than looping back to itself.
     */
    #[Test]
    public function promptLoginShowsTheLoginPageToASignedInUser(): void
    {
        // Given
        $this->signIn(self::user('alice'), new DateTimeImmutable('-1 hour'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'prompt' => 'login',
        ]));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $interaction = self::redirectedInteraction($response);

        // When
        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        // Then
        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('reauthentication_requested', $crawler->filter('[data-requirement]')->attr('data-requirement'));
    }

    /**
     * The consent form is protected against cross-site submission.
     */
    #[Test]
    public function theConsentFormRefusesAForeignSubmission(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $interaction = $this->beginAuthorization();

        // When
        $this->browser->request('POST', '/consent', [
            'interaction' => $interaction,
            'answer' => 'allow',
            '_token' => 'forged',
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
    }

    #[Test]
    public function aForeignSubmissionOfTheConsentFormCompletesNothing(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $interaction = $this->beginAuthorization();

        // When
        $this->browser->request('POST', '/consent', [
            'interaction' => $interaction,
            'answer' => 'allow',
            '_token' => 'forged',
        ]);

        // Then
        $pending = self::service('test.heidi.interactions', InteractionRepositoryInterface::class)->find($interaction) ?? static::fail('The interaction is gone.');
        static::assertFalse($pending->isCompleted());
    }

    /**
     * Architecture §4.3: a session that ended between the consent page and its answer, from another tab
     * or by an administrator, sends the user back to the login rather than granting anything.
     */
    #[Test]
    public function aBrowserWhoseSessionEndedGoesBackToTheLogin(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        $interaction = $this->beginAuthorization();
        $form = $this->consentPage($interaction)
            ->selectButton('Allow')
            ->form();
        $sessions = self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class);
        $stored = $sessions->find($session->id) ?? static::fail('The session is gone.');
        $stored->end(SessionEnd::User, new DateTimeImmutable());
        $sessions->save($stored);

        // When
        $this->browser->submit($form);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

    /**
     * The authorization request of the native client, parked: its interaction identifier.
     */
    private function beginAuthorization(): string
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters());

        return self::redirectedInteraction($this->browser->getResponse());
    }

    private function consentPage(string $interaction): Crawler
    {
        return $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
    }

    /**
     * The code the native client gets once alice signed in and allowed.
     */
    private function codeAllowedByAlice(): string
    {
        $interaction = $this->beginAuthorization();
        $this->signIn(self::user('alice'));
        $this->browser->submit($this->consentPage($interaction)->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
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
}
