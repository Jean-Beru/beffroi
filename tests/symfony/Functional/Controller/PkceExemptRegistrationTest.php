<?php

declare(strict_types=1);

namespace Heidi\Bundle\Tests\Functional\Controller;

use Heidi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Heidi\Oidc\Domain\Secret\DrawnSecret;
use Heidi\Oidc\Port\ClientRepositoryInterface;
use Heidi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function base64_encode;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * Decision 0017: the rule of decision 0006 stands, and the registration policy of a tenant may write the
 * named exception of decision 0008 on the confidential clients it registers. It is written on the
 * registration at the moment the policy creates it, read back from the row that kept it, and nothing a
 * client sends grants it.
 *
 * The policy of the tenant is read from the environment at runtime, the way the load budgets are, so
 * that a tenant carrying the exemption is a kernel this test names before it boots one.
 */
final class PkceExemptRegistrationTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    protected function setUp(): void
    {
        $_SERVER['HEIDI_TEST_REGISTRATION_PKCE_EXEMPTION'] = 'true';
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['HEIDI_TEST_REGISTRATION_PKCE_EXEMPTION'], $_ENV['HEIDI_TEST_REGISTRATION_PKCE_EXEMPTION']);
    }

    /**
     * OIDC Core §3.1.2.1 and decision 0017: a confidential client the policy registered signs in with no
     * "code_challenge" at all, which is what the 22 modules of the Dynamic OP plan send.
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
     * Decision 0017, RFC 9700 §2.1.1: a public client is never exempted, whatever the policy carries. Its
     * registration is not refused for that, and its authorization is refused without a challenge.
     */
    #[Test]
    public function aPublicClientThePolicyRegisteredIsNeverExempted(): void
    {
        // Given
        $registered = $this->register('none');
        $clientId = self::string($registered['client_id']);
        self::reload();

        // When
        $client = self::service('test.heidi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId);

        // Then
        static::assertTrue($client?->registration->requiresPkce);
    }

    /**
     * Decision 0017: the exemption is read back from the row that kept it, so a client the policy
     * registered is registered with it until that policy writes the registration again.
     */
    #[Test]
    public function theExemptionIsReadBackFromTheRowThatKeptIt(): void
    {
        // Given
        $registered = $this->register('client_secret_basic');
        $clientId = self::string($registered['client_id']);
        self::reload();

        // When
        $client = self::service('test.heidi.clients', ClientRepositoryInterface::class)->findByClientId(self::tenant(), $clientId);

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
        self::service('test.heidi.initial_access_tokens', InitialAccessTokenRepositoryInterface::class)
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
