<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use DateTimeImmutable;
use Heidi\Bundle\Http\AuthorizationResponder;
use Heidi\Core\Domain\Session\SessionEnd;
use Heidi\Core\Port\AuthenticationSessionRepositoryInterface;
use Heidi\Oidc\Port\InteractionRepositoryInterface;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §4.3 and §5.2, the acceptance criterion of the controllers: from /authorize to /userinfo
 * through the login and the consent pages, on the test kernel, with the module behind Doctrine. The
 * login itself is the one the firewall will do (#15): here the browser is handed a session the way the
 * firewall will hand it one.
 */
final class AuthorizationFlowTest extends BrowserTestCase
{
    /**
     * OIDC Core §3.1.2 to §3.1.3 and §5.3, RFC 7636, RFC 9207: the whole code flow of a public client
     * that requires consent.
     */
    #[Test]
    public function theCodeFlowGoesFromAuthorizeToUserInfoThroughLoginAndConsent(): void
    {
        self::signingKey();
        $user = self::user('alice');

        // 1. the authorization request parks an interaction and sends the browser to the login page
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        $interaction = self::redirectedInteraction($response);
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));

        // 2. the login page shows the form of the firewall, with its CSRF token
        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertCount(1, $crawler->filter('input[name="_username"]'));
        static::assertCount(1, $crawler->filter('input[name="_password"]'));
        static::assertNotSame('', $crawler->filter('input[name="_csrf_token"]')->attr('value'));
        static::assertSame('/login?interaction=' . $interaction, $crawler->filter('form')->attr('action'));

        // 3. once the browser holds a session, the login page resumes the interaction: consent is required
        $this->signIn($user);
        $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('/consent?interaction=' . $interaction, $response->headers->get('Location'));

        // 4. the consent page names the client, the user and every scope of the request
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        static::assertStringContainsString('alice', self::string($response->getContent()));
        static::assertSame(['openid', 'profile'], $crawler->filter('li[data-scope]')->extract(['data-scope']));
        static::assertSame($interaction, $crawler->filter('input[name="interaction"]')->attr('value'));

        // 5. the user allows: the code goes back to the client with "state" and "iss" (RFC 9207 §2)
        $this->browser->submit($crawler->selectButton('Allow')->form());
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        self::assertInteractionHeaders($response);
        $location = self::string($response->headers->get('Location'));
        static::assertStringStartsWith('http://127.0.0.1/callback?code=', $location);
        $query = self::redirectedQuery($response);
        static::assertSame('state-of-the-client', $query['state']);
        static::assertSame('https://op.test', $query['iss']);
        $code = $query['code'];

        // 6. the code is exchanged (RFC 6749 §4.1.3, RFC 7636 §4.5)
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'http://127.0.0.1/callback',
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('no-cache', $response->headers->get('Pragma'));
        $tokens = self::json($response);
        static::assertSame('Bearer', $tokens['token_type']);
        static::assertSame('openid profile', $tokens['scope']);
        static::assertIsString($tokens['id_token']);
        static::assertArrayNotHasKey('refresh_token', $tokens, 'A public client without offline_access gets no refresh token (architecture §4.5).');
        $accessToken = self::string($tokens['access_token']);

        // 7. the access token opens UserInfo (OIDC Core §5.3)
        $this->browser->request('GET', '/userinfo', server: [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame('application/json', $response->headers->get('Content-Type'));
        static::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        static::assertSame('alice-subject', self::json($response)['sub']);

        // 8. a second presentation of the code is a replay (RFC 6749 §4.1.2)
        $this->browser->request('POST', '/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => 'http://127.0.0.1/callback',
            'client_id' => 'native-app',
            'code_verifier' => self::CODE_VERIFIER,
        ]);
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_grant', self::json($response)['error']);

        // 9. the interaction is over: its pages are not reached again
        $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
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
        $this->signIn(self::user('alice'));

        $this->browser->request('POST', '/authorize', self::authorizationParameters('oidc-demo'));

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $location = self::string($response->headers->get('Location'));
        static::assertStringStartsWith('https://demo.test/login/check?code=', $location);
        static::assertSame('https://op.test', self::redirectedQuery($response)['iss']);
    }

    /**
     * RFC 6749 §4.1.2.1: the user denied, the client hears access_denied with its state and "iss".
     */
    #[Test]
    public function aDenialGoesBackToTheClient(): void
    {
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        $this->browser->submit($crawler->selectButton('Deny')->form());

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
        $this->browser->request('GET', '/authorize', self::authorizationParameters('unknown-client'));

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
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]));

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $query = self::redirectedQuery($response);
        static::assertStringStartsWith('http://127.0.0.1/callback?', self::string($response->headers->get('Location')));
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
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'prompt' => 'none',
        ]));

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('login_required', self::redirectedQuery($response)['error']);
    }

    /**
     * Architecture §4.3: an interaction is resumed only by the browser that began it. Another browser
     * holding the identifier is told nothing but that no request waits for it.
     */
    #[Test]
    public function anotherBrowserCannotResumeAnInteraction(): void
    {
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $other = self::browser();

        $other->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        $response = $other->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertStringContainsString('data-error="' . AuthorizationResponder::UNKNOWN_INTERACTION . '"', self::string($response->getContent()));
    }

    /**
     * A login page reached without an interaction, or with one that does not exist.
     */
    #[Test]
    public function theLoginPageNeedsAnInteraction(): void
    {
        $this->browser->request('GET', '/login');
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());

        $this->browser->request('GET', '/login', [
            'interaction' => 'does-not-exist',
        ]);
        static::assertSame(Response::HTTP_BAD_REQUEST, $this->browser->getResponse()->getStatusCode());
    }

    /**
     * Architecture §4.3: an interaction lives ten minutes; after that the user starts again from the
     * client, nothing is sent to the redirect URI.
     */
    #[Test]
    public function anExpiredInteractionIsShownToTheUser(): void
    {
        $interaction = $this->beginInteraction(new DateTimeImmutable('-20 minutes'), new DateTimeImmutable('-10 minutes'));

        $this->browser->request('GET', '/login', [
            'interaction' => $interaction->id,
        ]);

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
        $this->signIn(self::user('alice'), new DateTimeImmutable('-1 hour'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters('native-app', [
            'prompt' => 'login',
        ]));
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        $interaction = self::redirectedInteraction($response);

        $crawler = $this->browser->request('GET', '/login', [
            'interaction' => $interaction,
        ]);

        static::assertSame(Response::HTTP_OK, $this->browser->getResponse()->getStatusCode());
        static::assertSame('reauthentication_requested', $crawler->filter('[data-requirement]')->attr('data-requirement'));
    }

    /**
     * The consent form is protected against cross-site submission.
     */
    #[Test]
    public function theConsentFormRefusesAForeignSubmission(): void
    {
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());

        $this->browser->request('POST', '/consent', [
            'interaction' => $interaction,
            'answer' => 'allow',
            '_token' => 'forged',
        ]);

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        static::assertFalse($response->headers->has('Location'));
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
        $session = $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters());
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $form = $crawler->selectButton('Allow')
            ->form();
        $sessions = self::service('test.heidi.sessions', AuthenticationSessionRepositoryInterface::class);
        $stored = $sessions->find($session->id) ?? static::fail('The session is gone.');
        $stored->end(SessionEnd::User, new DateTimeImmutable());
        $sessions->save($stored);

        $this->browser->submit($form);

        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }
}
