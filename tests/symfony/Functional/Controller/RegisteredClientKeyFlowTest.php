<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Core\Tests\Fixture\Algorithms;
use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use Beffroi\Oidc\Tests\Fixture\ClientAssertions;
use Beffroi\Oidc\Tests\Fixture\ClientKeysBehindAJwksUri;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * OIDC Core §9, RFC 7523
 */
final class RegisteredClientKeyFlowTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    /**
     * OIDC Core §9, RFC 7591 §2
     *
     * @param array<string, mixed> $published
     */
    #[Test]
    #[DataProvider('provideKeySources')]
    public function aClientThatRegisteredItsKeysExchangesItsCode(array $published): void
    {
        // Given
        self::signingKey();
        $clientId = $this->register($published);
        $code = $this->codeAllowedByAlice($clientId);

        // When
        $this->exchange($clientId, $code, self::tenant()->issuer->value);

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertIsString(self::json($response)['access_token']);
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function provideKeySources(): iterable
    {
        yield 'inline, as every module of the plan registers them' => [
            [
                'jwks' => [
                    'keys' => ClientAssertions::publishedKeys(Algorithms::rs256())->keys,
                ],
            ],
        ];
        yield 'behind a jwks_uri (oidcc-registration-jwks-uri)' => [
            [
                'jwks_uri' => ClientKeysBehindAJwksUri::JWKS_URI,
            ],
        ];
    }

    /**
     * Decision 0016, draft-ietf-oauth-rfc7523bis §4
     */
    #[Test]
    public function anAssertionNamingTheTokenEndpointIsRefused(): void
    {
        // Given
        self::signingKey();
        $clientId = $this->register([
            'jwks' => [
                'keys' => ClientAssertions::publishedKeys(Algorithms::rs256())->keys,
            ],
        ]);
        $code = $this->codeAllowedByAlice($clientId);

        // When
        $this->exchange($clientId, $code, 'https://op.test/token');

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        static::assertSame('invalid_client', self::json($response)['error']);
    }

    /**
     * @param array<string, mixed> $published
     */
    private function register(array $published): string
    {
        $this->issue();
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::TOKEN,
            ],
            content: json_encode(
                $published
                + [
                    'redirect_uris' => [self::REDIRECT_URI],
                    'token_endpoint_auth_method' => 'private_key_jwt',
                    'scope' => 'openid profile',
                ],
                JSON_THROW_ON_ERROR,
            ),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::string(self::json($response)['client_id']);
    }

    private function issue(): void
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

    private function exchange(string $clientId, string $code, string $audience): void
    {
        $this->browser->request(
            'POST',
            '/token',
            ClientAssertions::parameters(ClientAssertions::signedWithKey(
                ClientAssertions::claims($clientId, $audience, self::currentSecond()),
                algorithm: Algorithms::rs256(),
            ))
            + [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
                'code_verifier' => self::CODE_VERIFIER,
                'client_id' => $clientId,
            ],
        );
    }
}
