<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use DateTimeImmutable;
use App\Http\AuthorizationResponder;
use Beffroi\Oidc\Port\InteractionRepositoryInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\DomCrawler\Crawler;
use Symfony\Component\HttpFoundation\Response;

/**
 * Architecture §4.3, §5.2, OIDC Core §3.1.2 to §3.1.3, §5.3, RFC 7636, RFC 9207
 */
final class AuthorizationFlowTest extends BrowserTestCase
{
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
     * RFC 9207 §2
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
     * RFC 6749 §4.1.3, RFC 7636 §4.5
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
     * RFC 6749 §5.1
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
     * Architecture §4.5
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
     * OIDC Core §5.3
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
     * RFC 6749 §4.1.2
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
     * RFC 6749 §4.1.2
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
     * Architecture §4.3, OIDC Core §3.1.2.1
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
     * RFC 6749 §4.1.2.1
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
        static::assertSame(
            [
                'error' => 'access_denied',
                'error_description' => 'The end user denied the request.',
                'state' => 'state-of-the-client',
                'iss' => 'https://op.test',
            ],
            self::redirectedQuery($response),
        );
    }

    /**
     * RFC 9700 §4.1, RFC 6749 §4.1.2.1
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
     * RFC 7636 §4.4.1, RFC 9207 §2
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
     * OIDC Core §3.1.2.6
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
     * OIDC Core §5.5.1.1, OIDC Core Error Code unmet_authentication_requirements §1, Decision 0010
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
     * Architecture §4.3
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
     * Architecture §4.3
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
     * OIDC Core §3.1.2.1
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
        $pending = self::service('test.beffroi.interactions', InteractionRepositoryInterface::class)
            ->find($interaction) ?? static::fail('The interaction is gone.');
        static::assertFalse($pending->isCompleted());
    }

    /**
     * Architecture §4.3
     */
    #[Test]
    public function aBrowserWhoseSessionEndedGoesBackToTheLogin(): void
    {
        // Given
        $session = $this->signIn(self::user('alice'));
        $interaction = $this->beginAuthorization();
        $form = $this->consentPage($interaction)->selectButton('Allow')->form();
        $this->endSession($session);

        // When
        $this->browser->submit($form);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('/login?interaction=' . $interaction, $response->headers->get('Location'));
    }

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
