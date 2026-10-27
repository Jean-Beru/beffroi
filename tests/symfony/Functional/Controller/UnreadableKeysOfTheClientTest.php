<?php

declare(strict_types=1);

namespace Beffroi\Bundle\Tests\Functional\Controller;

use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Event\AuthorizationCodeReplayed;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function base64_encode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §3.1.3.7 (issue #836): a client whose ID tokens are encrypted to a key it publishes behind a
 * "jwks_uri" that cannot be read. The token endpoint answers it the error of the server it is, and what the
 * request presented is not spent: the key is read before the code is, so the same request is served once
 * the set can be read again, and a second presentation of the code is never taken for a replay (RFC 6749
 * §4.1.2).
 *
 * The client registers itself: a declared client that asks for an encrypted document publishes its keys
 * inline, which the boot checks, and nothing of this kernel answers behind a "jwks_uri" but the one the
 * fixture names (ClientKeysBehindAJwksUri), so the one this client registers cannot be read.
 */
final class UnreadableKeysOfTheClientTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://unreadable.test/callback';

    /**
     * RFC 6749 §4.1.2: a code is spent by the presentation that exchanges it, and one that could not be
     * answered exchanged nothing. Presented again, it is answered as it was the first time, and nothing
     * revokes the grant it names.
     */
    #[Test]
    public function aCodeTheProviderCouldNotAnswerIsNotTakenForAReplay(): void
    {
        // Given
        self::signingKey();
        [$clientId, $secret] = $this->register();
        $code = $this->codeAllowedByAlice($clientId);
        $this->exchange($clientId, $secret, $code);
        self::forgetEvents();

        // When
        $this->exchange($clientId, $secret, $code);

        // Then
        static::assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $this->browser->getResponse()->getStatusCode());
        static::assertSame([], self::events(AuthorizationCodeReplayed::class));
    }

    /**
     * The identifier and the secret the provider drew for a client that authenticates with a secret and
     * asks for its ID tokens encrypted to a key behind a "jwks_uri" nothing answers.
     *
     * @return array{string, string}
     */
    private function register(): array
    {
        self::service('test.beffroi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
            ->save(new InitialAccessToken(
                Uuid::v7(),
                self::tenant(),
                DrawnSecret::digestOf(self::TOKEN),
                'The team that integrates',
                1,
                self::currentSecond(),
                self::currentSecond()->modify('+1 day'),
            ));
        self::reload();
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::TOKEN,
            ],
            content: json_encode(
                [
                    'redirect_uris' => [self::REDIRECT_URI],
                    'token_endpoint_auth_method' => 'client_secret_basic',
                    'scope' => 'openid profile',
                    'jwks_uri' => 'https://unreadable.test/jwks.json',
                    'id_token_encrypted_response_alg' => 'ECDH-ES+A256KW',
                    'id_token_encrypted_response_enc' => 'A256GCM',
                ],
                JSON_THROW_ON_ERROR,
            ),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));
        $registration = self::json($response);

        return [self::string($registration['client_id']), self::string($registration['client_secret'])];
    }

    private function codeAllowedByAlice(string $clientId): string
    {
        $this->signIn(self::user('alice'));
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => self::REDIRECT_URI,
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->browser->submit($this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ])->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }

    private function exchange(string $clientId, string $secret, string $code): void
    {
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . $secret),
            ],
        );
    }
}
