<?php

declare(strict_types=1);

namespace App\Tests\Symfony\Functional\Controller;

use Beffroi\Oidc\Domain\Client\Registration\InitialAccessToken;
use Beffroi\Oidc\Domain\Secret\DrawnSecret;
use Beffroi\Oidc\Port\ClientRepositoryInterface;
use Beffroi\Oidc\Port\InitialAccessTokenRepositoryInterface;
use function array_diff_key;
use function array_flip;
use function json_encode;
use const JSON_THROW_ON_ERROR;
use PHPUnit\Framework\Attributes\Test;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §2
 */
final class DefaultScopeRegistrationTest extends BrowserTestCase
{
    private const string TOKEN = 'a-value-the-tenant-handed-out';

    private const string REDIRECT_URI = 'https://registered.test/callback';

    private const string DEFAULT_SCOPE = 'openid profile offline_access';

    protected function setUp(): void
    {
        $_SERVER['BEFFROI_TEST_REGISTRATION_DEFAULT_SCOPE'] = self::DEFAULT_SCOPE;
        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        unset($_SERVER['BEFFROI_TEST_REGISTRATION_DEFAULT_SCOPE'], $_ENV['BEFFROI_TEST_REGISTRATION_DEFAULT_SCOPE']);
    }

    /**
     * RFC 7591 §2
     */
    #[Test]
    public function aClientThatRegistersNoScopeTakesWhatTheTenantWrote(): void
    {
        // Given
        $registered = $this->register([]);
        self::reload();

        // When
        $client = self::service('test.beffroi.clients', ClientRepositoryInterface::class)
            ->findByClientId(self::tenant(), self::string($registered['client_id']));

        // Then
        static::assertSame(self::DEFAULT_SCOPE, (string) $client?->registration->allowedScopes);
    }

    /**
     * RFC 7591 §3.2.1
     */
    #[Test]
    public function theClientIsAnsweredTheScopesTheTenantWrote(): void
    {
        // When
        $registered = $this->register([]);

        // Then
        static::assertSame(self::DEFAULT_SCOPE, $registered['scope'] ?? null);
    }

    /**
     * RFC 7592 §2.2
     */
    #[Test]
    public function aClientThatSendsBackWhatItWasAnsweredKeepsTheScopesTheTenantWrote(): void
    {
        // Given
        $registered = $this->register([]);

        // When
        $this->browser->request(
            'PUT',
            self::string($registered['registration_client_uri']),
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . self::string($registered['registration_access_token']),
            ],
            content: json_encode(
                array_diff_key($registered, array_flip([
                    'registration_access_token',
                    'registration_client_uri',
                    'client_secret_expires_at',
                    'client_id_issued_at',
                ])),
                JSON_THROW_ON_ERROR,
            ),
        );

        // Then
        $response = $this->browser->getResponse();
        static::assertSame(Response::HTTP_OK, $response->getStatusCode(), self::string($response->getContent()));
        static::assertSame(self::DEFAULT_SCOPE, self::json($response)['scope'] ?? null);
    }

    #[Test]
    public function aClientThatNamesItsOwnScopeKeepsIt(): void
    {
        // Given
        $registered = $this->register([
            'scope' => 'openid',
        ]);
        self::reload();

        // When
        $client = self::service('test.beffroi.clients', ClientRepositoryInterface::class)
            ->findByClientId(self::tenant(), self::string($registered['client_id']));

        // Then
        static::assertSame('openid', (string) $client?->registration->allowedScopes);
    }

    #[Test]
    public function suchAClientMayAskForTheScopesTheTenantWrote(): void
    {
        // Given
        $registered = $this->register([
            'grant_types' => ['authorization_code', 'refresh_token'],
        ]);
        $this->signIn(self::user('alice'));

        // When
        $this->browser->request('GET', '/authorize', self::authorizationParameters(self::string($registered['client_id']), [
            'redirect_uri' => self::REDIRECT_URI,
            'scope' => 'openid offline_access',
        ]));
        $interaction = self::redirectedInteraction($this->browser->getResponse());
        $this->browser->submit($this->browser->request('GET', '/consent', [
            'interaction' => $interaction,
        ])->selectButton('Allow')->form());

        // Then
        static::assertIsString(self::redirectedQuery($this->browser->getResponse())['code'] ?? null);
    }

    /**
     * @param array<string, mixed> $members
     *
     * @return array<string, mixed>
     */
    private function register(array $members): array
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
                $members
                + [
                    'redirect_uris' => [self::REDIRECT_URI],
                    'token_endpoint_auth_method' => 'client_secret_basic',
                ],
                JSON_THROW_ON_ERROR,
            ),
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
}
