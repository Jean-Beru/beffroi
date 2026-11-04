<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function base64_encode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0017
 */
final class PkceExemptRegistrationTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_REGISTRATION_PKCE_EXEMPTION'] = 'true';
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_REGISTRATION_PKCE_EXEMPTION'], $_ENV['BEFFROI_TEST_REGISTRATION_PKCE_EXEMPTION']);
    }

    /**
     * OIDC Core §3.1.2.1, Decision 0017
     */
    #[Test]
    public function aConfidentialClientThePolicyRegisteredSignsInWithoutAChallenge(): void
    {
        // Given
        self::signingKey();
        $registered = $this->register('client_secret_basic');
        $clientId = self::string($registered['client_id']);
        $this->signIn(self::user('alice'));
        $code = $this->codeAllowedByAlice($clientId);

        // When
        $this->browser->request(
            'POST',
            '/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => self::REDIRECT_URI,
            ],
            server: [
                'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode($clientId . ':' . self::string($registered['client_secret'])),
            ],
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertIsString(self::json($response)['access_token']);
    }

    /**
     * Decision 0017, RFC 9700 §2.1.1
     */
    #[Test]
    public function aPublicClientThePolicyRegisteredIsNeverExempted(): void
    {
        // Given
        $registered = $this->register('none');
        $clientId = self::string($registered['client_id']);
        self::reload();

        // When
        $client = self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId);

        // Then
        static::assertTrue($client?->registration->requiresPkce);
    }

    /**
     * Decision 0017
     */
    #[Test]
    public function theExemptionIsReadBackFromTheRowThatKeptIt(): void
    {
        // Given
        $registered = $this->register('client_secret_basic');
        $clientId = self::string($registered['client_id']);
        self::reload();

        // When
        $client = self::service('test.beffroi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId);

        // Then
        static::assertFalse($client?->registration->requiresPkce);
    }

    /**
     * @return array<string, mixed>
     */
    private function register(string $method): array
    {
        $this->issue();
        $this->browser->request(
            'POST',
            '/register',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::TOKEN,
            ],
            content: json_encode([
                'redirect_uris' => [self::REDIRECT_URI],
                'token_endpoint_auth_method' => $method,
                'scope' => 'openid profile',
            ], JSON_THROW_ON_ERROR),
        );
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_CREATED, $response->getStatusCode(), self::string($response->getContent()));

        return self::json($response);
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
        $this->browser->request('GET', '/authorize', self::authorizationParameters($clientId, [
            'redirect_uri' => self::REDIRECT_URI,
            'code_challenge' => null,
            'code_challenge_method' => null,
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->browser->submit($this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ])->selectButton('Allow')->form());

        return self::redirectedQuery($this->browser->getResponse())['code'] ?? static::fail('The client got no code.');
    }
}
