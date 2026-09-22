<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;

/**
 * Decision 0008, the named exception to the PKCE rule of decision 0006: a confidential client registered
 * with "requires_pkce: false" runs the code flow of OIDC Core §3.1 without a code_challenge, the way the
 * OpenID certification profiles do; what it sends is verified all the same (RFC 9700 §2.1.1) and a
 * code_verifier for a code issued without a challenge is refused (RFC 9700 §4.8.2). One step per test,
 * on the test kernel, the "legacy-app" client of its configuration.
 */
final class PkceExemptFlowTest extends BrowserTestCase
{
    private const string CLIENT_ID = 'legacy-app';

    private const string SECRET = 'legacy-secret-of-at-least-32-characters-long';

    private const string REDIRECT_URI = 'https://legacy.test/callback';

    /**
     * RFC 7636 §4.4.1 would refuse the request; decision 0008 parks it like any other.
     */
    #[Test]
    public function anAuthorizationRequestWithoutAChallengeIsParked(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::legacyParameters());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith('/login?interaction=', self::string($response->headers->get('Location')));
    }

    #[Test]
    public function theCodeGoesBackToTheClientWithoutAChallenge(): void
    {
        // Given
        $this->signIn(self::user('alice'));
        $interaction = $this->beginAuthorization();
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);

        // When
        $this->browser->submit($crawler->selectButton('Allow')->form());

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertStringStartsWith(self::REDIRECT_URI . '?code=', self::string($response->headers->get('Location')));
        static::assertSame('https://op.test', self::redirectedQuery($response)['iss']);
    }

    /**
     * RFC 6749 §4.1.3 without RFC 7636 §4.5: no code_verifier in the token request.
     */
    #[Test]
    public function theCodeIsExchangedWithoutAVerifier(): void
    {
        // Given
        self::signingKey();
        $code = $this->codeAllowedByAlice();

        // When
        $this->exchange($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        $tokens = self::json($response);
        static::assertSame('Bearer', $tokens['token_type']);
        static::assertIsString($tokens['id_token']);
        static::assertIsString($tokens['access_token']);
    }

    /**
     * RFC 9700 §4.8.2: a code_verifier is accepted only if a code_challenge was present in the
     * authorization request.
     */
    #[Test]
    public function aVerifierIsRefusedForACodeIssuedWithoutAChallenge(): void
    {
        // Given
        self::signingKey();
        $code = $this->codeAllowedByAlice();

        // When
        $this->exchange($code, [
            'code_verifier' => self::CODE_VERIFIER,
        ]);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_grant', self::json($response)['error']);
    }

    /**
     * RFC 9700 §2.1.1: a challenge the client sends binds the code, exception or not.
     */
    #[Test]
    public function aChallengeTheClientSendsIsEnforcedAtTheTokenEndpoint(): void
    {
        // Given
        self::signingKey();
        $code = $this->codeAllowedByAlice([
            'code_challenge' => self::codeChallenge(),
            'code_challenge_method' => 'S256',
        ]);

        // When
        $this->exchange($code);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        static::assertSame('invalid_grant', self::json($response)['error']);
    }

    /**
     * Decision 0006 stands: "plain" does not exist, for this client either (RFC 7636 §4.3).
     */
    #[Test]
    public function aPlainChallengeIsRefusedForThisClientToo(): void
    {
        // When
        $this->browser->request('GET', '/authorize', self::legacyParameters([
            'code_challenge' => self::codeChallenge(),
            'code_challenge_method' => 'plain',
        ]));

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_FOUND, $response->getStatusCode());
        static::assertSame('invalid_request', self::redirectedQuery($response)['error']);
    }

    /**
     * The request of the legacy client: no code_challenge unless the test adds one.
     *
     * @param array<string, string|null> $parameters
     *
     * @return array<string, string>
     */
    private static function legacyParameters(array $parameters = []): array
    {
        return self::authorizationParameters(
            self::CLIENT_ID,
            $parameters
            + [
                'redirect_uri' => self::REDIRECT_URI,
                'code_challenge' => null,
                'code_challenge_method' => null,
            ],
        );
    }

    /**
     * @param array<string, string|null> $parameters
     */
    private function beginAuthorization(array $parameters = []): string
    {
        $this->browser->request('GET', '/authorize', self::legacyParameters($parameters));

        return self::redirectedInteraction($this->browser->getResponse());
    }

    /**
     * The code the legacy client gets once alice signed in and allowed.
     *
     * @param array<string, string|null> $parameters
     */
    private function codeAllowedByAlice(array $parameters = []): string
    {
        $this->signIn(self::user('alice'));
        $interaction = $this->beginAuthorization($parameters);
        $crawler = $this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ]);
        $this->browser->submit($crawler->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    /**
     * The token request of the legacy client, client_secret_post, without a code_verifier unless given.
     *
     * @param array<string, string> $parameters
     */
    private function exchange(string $code, array $parameters = []): void
    {
        $this->browser->request(
            'POST',
            '/token',
            $parameters
            + [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'client_id' => self::CLIENT_ID,
                'client_secret' => self::SECRET,
            ],
        );
    }
}
