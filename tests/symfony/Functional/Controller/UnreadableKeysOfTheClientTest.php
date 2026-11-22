<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

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
 * OIDC Core §3.1.3.7, RFC 6749 §4.1.2
 */
final class UnreadableKeysOfTheClientTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://unreadable.test/callback';

    /**
     * RFC 6749 §4.1.2
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
